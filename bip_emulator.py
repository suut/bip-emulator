#!/usr/bin/env python3
# coding: utf-8

import logging
import shlex
from dataclasses import dataclass

logger = logging.getLogger('bip-emulator')

from time import time, sleep
import socket

from enum import IntEnum, Enum, auto

from tlv_utils import parse_tag, parse_tags, parse_length, parse_comprehension_tlv_tag, encode_tlv, CTLV
from smartcard_utils import APDUException, Smartcard, es10x

import asyncio
import sys
import threading
import argparse
import curses
import curses.textpad
import os
import smartcard.CardConnection
import smartcard.ATR
import smartcard.Exceptions
import traceback


parser = argparse.ArgumentParser(description='BIP modem emulator', epilog='Note: the PIN code will be used for all '
                                                                          'profiles that have the PIN enabled. Disable '
                                                                          'the PIN first on the SIM if that is '
                                                                          'inconvenient.')
parser.add_argument('--mcc', default='204', help='Mobile country code (default %(default)s)')
parser.add_argument('--mnc', default='04', help='Mobile network code (default %(default)s)')
parser.add_argument('--imei', default='356358231187560', help='IMEI (default %(default)s)')
parser.add_argument('-p', '--pin', default=None, help='PIN code')
parser.add_argument('--network', choices=('none', '2G', '3G', '4G', '5G'), default='4G', help='Network type (default %(default)s; choices %(choices)s)')
parser.add_argument('-r', '--reader', metavar='N', default='auto', help='Reader index or name (default %(default)s, give the value \'list\' to list readers)')
args = parser.parse_args()

if args.pin is not None and len(args.pin) > 8:
    sys.exit('PIN is too long, maximum 8 characters')
if args.pin is not None and not all(c in '1234567890' for c in args.pin):
    sys.exit('PIN must be numerical')

reader_index = None
if args.reader == 'list':
    readers = smartcard.System.readers()
    for i, reader in enumerate(readers):
        print(f'[{i}]: {reader}')
    sys.exit(0)
elif args.reader == 'auto':
    readers = smartcard.System.readers()

    reader_with_t0_card = None
    reader_with_card = None
    reader_with_euicc_card = None
    for i, reader in enumerate(readers):
        conn: smartcard.CardConnection.CardConnection = reader.createConnection()
        try:
            conn.connect()
            if reader_with_card is None:
                reader_with_card = i
            atr = smartcard.ATR.ATR(conn.getATR())
            if atr.getSupportedProtocols().get('T=0', False) and reader_with_t0_card is None:
                reader_with_t0_card = i
            for j, td in enumerate(atr.TD):
                if td is not None and td & 0x0F == 15:
                    if j < len(atr.TB) - 1 and atr.TB[j + 1] is not None and atr.TB[j + 1] & 0x82 == 0x82:
                        if reader_with_euicc_card is None:
                            reader_with_euicc_card = i
                    break
            conn.disconnect()
            if reader_with_euicc_card is not None:
                break

        except (smartcard.Exceptions.NoCardException, smartcard.Exceptions.CardConnectionException):
            pass

    if (reader_index := next(filter(lambda i: i is not None, (reader_with_euicc_card,
                                                              reader_with_t0_card,
                                                              reader_with_card)), None)) is None:
        sys.exit('No reader with inserted card found')

else:
    reader_index = int(args.reader)

if args.network != '4G':
    raise NotImplementedError(f'Network {args.network} not implemented yet')

refresh_event = asyncio.Event()
sc = Smartcard(refresh_event=refresh_event, reader=reader_index)
sc.connect()

USIM_AID = bytes.fromhex('A0000000871002')
EF_LOCI = bytes.fromhex('6F7E')
EF_PSLOCI = bytes.fromhex('6F73')
EF_EPSLOCI = bytes.fromhex('6FE3')

class ACT(IntEnum):
    GSM = 0x00
    UTRAN = 0x03
    EUTRAN = 0x08
    NR = 0x0A
    # TODO: put the rest

class RegistrationType(IntEnum):
    EPS_ATTACH = 0x09
    # TODO: put the rest


class RegistrationRejectionCode(IntEnum):
    PLMN_NOT_ALLOWED = 0x0B  # E-UTRAN
    # TODO: find the rest as Reject Cause information element in TS 24.008 for GERAN/UTRAN
    # TODO: find the rest as EMM Cause information element in TS 24.301 for E-UTRAN
    # TODO: find the rest as 5GMM Cause information element in TS 24.501 for NG-RAN

class DeviceIdentity(IntEnum):
    KEYPAD = 0x01
    DISPLAY = 0x02
    EARPIECE = 0x03
    ADDITIONAL_CARD_READER   = 0x10
    ADDITIONAL_CARD_READER_0 = 0x10
    ADDITIONAL_CARD_READER_1 = 0x11
    ADDITIONAL_CARD_READER_2 = 0x12
    ADDITIONAL_CARD_READER_3 = 0x13
    ADDITIONAL_CARD_READER_4 = 0x14
    ADDITIONAL_CARD_READER_5 = 0x15
    ADDITIONAL_CARD_READER_6 = 0x16
    ADDITIONAL_CARD_READER_7 = 0x17
    CHANNEL = 0x20
    CHANNEL_0 = 0x21
    CHANNEL_1 = 0x21
    CHANNEL_2 = 0x22
    CHANNEL_3 = 0x23
    CHANNEL_4 = 0x24
    CHANNEL_5 = 0x25
    CHANNEL_6 = 0x26
    CHANNEL_7 = 0x27
    ECAT_CLIENT = 0x30
    ECAT_CLIENT_1 = 0x31
    ECAT_CLIENT_2 = 0x32
    ECAT_CLIENT_3 = 0x33
    ECAT_CLIENT_4 = 0x34
    ECAT_CLIENT_5 = 0x35
    ECAT_CLIENT_6 = 0x36
    ECAT_CLIENT_7 = 0x37
    ECAT_CLIENT_8 = 0x38
    ECAT_CLIENT_9 = 0x39
    ECAT_CLIENT_10 = 0x3A
    ECAT_CLIENT_11 = 0x3B
    ECAT_CLIENT_12 = 0x3C
    ECAT_CLIENT_13 = 0x3D
    ECAT_CLIENT_14 = 0x3E
    ECAT_CLIENT_15 = 0x3F
    UICC = 0x81
    TERMINAL = 0x82
    NETWORK = 0x83


class ResultCode(IntEnum):
    # 0X and 1X: command has been performed
    COMMAND_PERFORMED_SUCCESSFULLY = 0x00
    COMMAND_PERFORMED_WITH_PARTIAL_COMPREHENSION = 0x01
    COMMAND_PERFORMED_WITH_MISSING_INFORMATION = 0x02
    REFRESH_PERFORMED_WITH_ADDITIONAL_EFS_READ = 0x03
    COMMAND_PERFORMED_SUCCESSFULLY_REQUESTED_ICON_COULD_NOT_BE_DISPLAYED = 0x04
    COMMAND_PERFORMED_BUT_MODIFIED_BY_CALL_CONTROL_BY_NAA = 0x05
    COMMAND_PERFORMED_SUCCESSFULLY_LIMITED_SERVICE = 0x06
    COMMAND_PERFORMED_WITH_MODIFICATION = 0x07
    REFRESH_PERFORMED_BUT_INDICATED_NAA_WAS_NOT_ACTIVE = 0x08
    COMMAND_PERFORMED_SUCCESSFULLY_TONE_NOT_PLAYED = 0x09
    PROACTIVE_UICC_SESSION_TERMINATED_BY_THE_USER = 0x10
    BACKWARD_MOVE_IN_THE_PROACTIVE_UICC_SESSION_REQUESTED_BY_THE_USER = 0x11
    NO_RESPONSE_FROM_USER = 0x12
    HELP_INFORMATION_REQUIRED_BY_THE_USER = 0x13
    USSD_OR_SS_TRANSACTION_TERMINATED_BY_THE_USER = 0x14

    # 2X: indicates to the UICC that it may be worth re-trying the command at a later opportunity
    TERMINAL_CURRENTLY_UNABLE_TO_PROCESS_COMMAND = 0x20
    NETWORK_CURRENTLY_UNABLE_TO_PROCESS_COMMAND = 0x21
    USER_DID_NOT_ACCEPT_THE_PROACTIVE_COMMAND = 0x22
    USER_CLEARED_DOWN_CALL_BEFORE_CONNECTION_OR_NETWORK_RELEASE = 0x23
    ACTION_IN_CONTRADICTION_WITH_THE_CURRENT_TIMER_STATE = 0x24
    INTERACTION_WITH_CALL_CONTROL_BY_NAA_TEMPORARY_PROBLEM = 0x25
    LAUNCH_BROWSER_GENERIC_ERROR = 0x26
    MMS_TEMPORARY_PROBLEM = 0x27

    # 3X: indicates that it is not worth the UICC re-trying with an identical command
    COMMAND_BEYOND_TERMINAL_CAPABILITIES = 0x30
    COMMAND_TYPE_NOT_UNDERSTOOD_BY_TERMINAL = 0x31
    COMMAND_DATA_NOT_UNDERSTOOD_BY_TERMINAL = 0x32
    COMMAND_NUMBER_NOT_KNOWN_BY_TERMINAL = 0x33
    SS_RETURN_ERROR = 0x34
    SMS_RP_ERROR = 0x35
    ERROR_REQUIRED_VALUES_ARE_MISSING = 0x36
    USSD_RETURN_ERROR = 0x37
    MULTIPLECARD_COMMANDS_ERROR = 0x38
    INTERACTION_WITH_CALL_CONTROL_BY_USIM_PERMANENT_PROBLEM = 0x39
    BEARER_INDEPENDENT_PROTOCOL_ERROR = 0x3A
    ACCESS_TECHNOLOGY_UNABLE_TO_PROCESS_COMMAND = 0x3B
    FRAMES_ERROR = 0x3C
    MMS_ERROR = 0x3D


class ResultExtra(IntEnum):
    NO_SERVICE = 0x04


class Event(IntEnum):
    MT_CALL = 0x00
    CALL_CONNECTED = 0x01
    CALL_DISCONNECTED = 0x02
    LOCATION_STATUS = 0x03
    USER_ACTIVITY = 0x04
    IDLE_SCREEN_AVAILABLE = 0x05
    CARD_READER_STATUS = 0x06
    LANGUAGE_SELECTION = 0x07
    BROWSER_TERMINATION = 0x08
    DATA_AVAILABLE = 0x09
    CHANNEL_STATUS = 0x0A
    ACCESS_TECHNOLOGY_CHANGE = 0x0B
    DISPLAY_PARAMETERS_CHANGED = 0x0C
    LOCAL_CONNECTION = 0x0D
    NETWORK_SEARCH_MODE_CHANGE = 0x0E
    BROWSING_STATUS = 0x0F
    FRAMES_INFORMATION_CHANGE = 0x10
    IWLAN_ACCESS_STATUS = 0x11
    NETWORK_REJECTION = 0x12
    HCI_CONNECTIVITY_EVENT = 0x13
    ACCESS_TECHNOLOGY_CHANGE_MULTIPLE = 0x14
    CSG_CELL_SELECTION = 0x15
    CONTACTLESS_STATE_REQUEST = 0x16
    IMS_REGISTRATION = 0x17
    IMS_INCOMING_DATA = 0x18
    PROFILE_CONTAINER = 0x19
    SECURED_PROFILE_CONTAINER = 0x1B
    POLL_INTERVAL_NEGOTIATION = 0x1C
    DATA_CONNECTION_STATUS_CHANGE = 0x1D


class Command(IntEnum):
    REFRESH = 0x01
    MORE_TIME = 0x02
    POLL_INTERVAL = 0x03
    POLLING_OFF = 0x04
    SET_UP_EVENT_LIST = 0x05
    SET_UP_CALL = 0x10
    SEND_SS = 0x11
    SEND_USSD = 0x12
    SEND_SHORT_MESSAGE = 0x13
    SEND_DTMF = 0x14
    LAUNCH_BROWSER = 0x15
    GEOGRAPHICAL_LOCATION_REQUEST = 0x16
    PLAY_TONE = 0x20
    DISPLAY_TEXT = 0x21
    GET_INKEY = 0x22
    GET_INPUT = 0x23
    SELECT_ITEM = 0x24
    SET_UP_MENU = 0x25
    PROVIDE_LOCAL_INFORMATION = 0x26
    TIMER_MANAGEMENT = 0x27
    SET_UP_IDLE_MODE_TEXT = 0x28
    PERFORM_CARD_APDU = 0x30
    POWER_ON_CARD = 0x31
    POWER_OFF_CARD = 0x32
    GET_READER_STATUS = 0x33
    RUN_AT_COMMAND = 0x34
    LANGUAGE_NOTIFICATION = 0x35
    OPEN_CHANNEL = 0x40
    CLOSE_CHANNEL = 0x41
    RECEIVE_DATA = 0x42
    SEND_DATA = 0x43
    GET_CHANNEL_STATUS = 0x44
    SERVICE_SEARCH = 0x45
    GET_SERVICE_INFORMATION = 0x46
    DECLARE_SERVICE = 0x47
    SET_FRAMES = 0x50
    GET_FRAMES_STATUS = 0x51
    RETRIEVE_MULTIMEDIA_MESSAGE = 0x60
    SUBMIT_MULTIMEDIA_MESSAGE = 0x61
    DISPLAY_MULTIMEDIA_MESSAGE = 0x62
    ACTIVATE = 0x70
    CONTACTLESS_STATE_CHANGED = 0x71
    COMMAND_CONTAINER = 0x72
    ENCAPSULATED_SESSION_CONTROL = 0x73
    LSI_COMMAND = 0x79


CommandDetails = CTLV.make_type('CommandDetails', 0x01, True, {'command_number': (0, 1, int), 'command': (1, 1, int), 'command_data': (2, 1, int)})  # type: ignore
DeviceIdentities = CTLV.make_type('DeviceIdentities', 0x02, False, {'source': (0, 1, int), 'destination': (1, 1, int)})  # type: ignore
Result = CTLV.make_type('Result', 0x03, True, {'result': (0, 1, int), 'extra': (1, ..., int)})  # type: ignore
Duration = CTLV.make_type('Duration', 0x04, False, {'unit': (0, 1, int), 'interval': (1, 1, int)})  # type: ignore
LocalInformation = CTLV.make_type('LocalInformation', 0x13, False)
Imei = CTLV.make_type('Imei', 0x14, False)
EventList = CTLV.make_type('EventList', 0x19, False)
TimerIdentifier = CTLV.make_type('TimerIdentifier', 0x24, False, {'identifier': (0, 1, int)})  # type: ignore
TimerValue = CTLV.make_type('TimerValue', 0x25, False)
ChannelData = CTLV.make_type('ChannelData', 0x36, False)
ChannelStatus = CTLV.make_type('ChannelStatus', 0x38, False, {'status': (0, 1, int), 'extra': (1, 1, int)})  # type: ignore
ChannelDataLength = CTLV.make_type('ChannelDataLength', 0x37, False, {'length': (0, 1, int)})  # type: ignore
BearerDescription = CTLV.make_type('BearerDescription', 0x35, False, {'bearer_type': (0, 1, int), 'description': (1, ..., bytes)})  # type: ignore
BufferSize = CTLV.make_type('BufferSize', 0x39, False, {'size': (0, 2, int)})  # type: ignore
DnsServerAddress = CTLV.make_type('DnsServerAddress', 0x40, False, {'address_type': (0, 1, int), 'address': (1, ..., bytes)})  # type: ignore
InterfaceTransportLevel = CTLV.make_type('InterfaceTransportLevel', 0x3C, False, {'protocol': (0, 1, int), 'port': (1, 2, int)})  # type: ignore
OtherAddress = CTLV.make_type('OtherAddress', 0x3E, False, {'address_type': (0, 1, int), 'address': (1, ..., bytes)})  # type: ignore
LocationStatus = CTLV.make_type('LocationStatus', 0x1B, True, {'status': (0, 1, int)})  # type: ignore
TrackingAreaIdentification = CTLV.make_type('TrackingAreaIdentification', 0x7D, False, {'mcc_mnc': (0, 3, bytes), 'tac': (3, ..., bytes)})  # type: ignore
UpdateAttachRegistrationType = CTLV.make_type('UpdateAttachRegistrationType', 0x74, False, {'type': (0, 1, int)})  # type: ignore
RejectionCauseCode = CTLV.make_type('RejectionCauseCode', 0x75, False, {'code': (0, 1, int)})  # type: ignore
AccessTechnology = CTLV.make_type('AccessTechnology', 0x3F, False, {'technologies': (0, ..., bytes)})

class NetworkType(Enum):
    disconnected = auto()
    geran = auto()
    utran = auto()
    eutran = auto()
    ngran = auto()


network_type = NetworkType.eutran

network_friendly_names = {
    NetworkType.disconnected: 'Disconnected',
    NetworkType.geran: '2G',
    NetworkType.utran: '3G',
    NetworkType.eutran: '4G',
    NetworkType.ngran: '5G'
}

has_5g = False


class EUTRANLocation:
    def __init__(self,
                 mcc: str,
                 mnc: str,
                 tac: str = '797E',
                 mme_group_id: str = '8000',
                 mme_code: str = '60',
                 m_tmsi: str = 'EC4AC9CC',
                 enb_id: int = 123456,
                 cell_id: int = 42):
        self.mcc = mcc
        self.mnc = mnc
        self.tac = tac
        self.mme_group_id = mme_group_id
        self.mme_code = mme_code
        self.m_tmsi = m_tmsi
        self.enb_id = enb_id
        self.cell_id = cell_id

    @property
    def mcc_mnc(self) -> bytes:
        mcc = self.mcc
        mnc = self.mnc
        assert len(mcc) == 3
        assert 2 <= len(mnc) <= 3

        if len(mnc) == 2:
            mnc = mnc + 'F'

        return bytes.fromhex(f'{mcc[1]}{mcc[0]}{mnc[2]}{mcc[2]}{mnc[1]}{mnc[0]}')

    @property
    def guti(self) -> bytes:
        return bytes.fromhex('0BF6') + self.mcc_mnc + bytes.fromhex(self.mme_group_id) + bytes.fromhex(self.mme_code) + bytes.fromhex(self.m_tmsi)

    @property
    def tai(self) -> bytes:
        return self.mcc_mnc + bytes.fromhex(self.tac)

    @property
    def eci(self) -> bytes:
        assert self.cell_id < 256
        return ((((self.enb_id << 8) | self.cell_id) << 4) | 0x0F).to_bytes(byteorder='big', length=4)

location = EUTRANLocation(args.mcc, args.mnc)
imei = args.imei


def select_usim(usim_aid: bytes) -> bytes:
    return sc.transmit(cla=0x00, ins=0xA4, p1=0x04, p2=0x04, data=usim_aid, le=0)


def update_location_eutran(loc: EUTRANLocation):
    # Zero out EF.LOCI
    sc.transmit(cla=0x00, ins=0xA4, p1=0x00, p2=0x04, data=EF_LOCI, le=0x00)
    sc.transmit(cla=0x00, ins=0xD6, p1=0x00, p2=0x00, data=bytes.fromhex('FFFFFFFFFFFFFFFFFFFF01'))

    # Zero out EF.PSLOCI
    sc.transmit(cla=0x00, ins=0xA4, p1=0x00, p2=0x04, data=EF_PSLOCI, le=0x00)
    sc.transmit(cla=0x00, ins=0xD6, p1=0x00, p2=0x00, data=bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFF01'))

    # Set EF.EPSLOCI
    sc.transmit(cla=0x00, ins=0xA4, p1=0x00, p2=0x04, data=EF_EPSLOCI, le=0x00)
    sc.transmit(cla=0x00, ins=0xD6, p1=0x00, p2=0x00, data=loc.guti + loc.tai + b'\x00')


def update_location_no_service():
    # Zero out EF.LOCI
    sc.transmit(cla=0x00, ins=0xA4, p1=0x00, p2=0x04, data=EF_LOCI, le=0x00)
    sc.transmit(cla=0x00, ins=0xD6, p1=0x00, p2=0x00, data=bytes.fromhex('FFFFFFFFFFFFFFFFFFFF01'))

    # Zero out EF.PSLOCI
    sc.transmit(cla=0x00, ins=0xA4, p1=0x00, p2=0x04, data=EF_PSLOCI, le=0x00)
    sc.transmit(cla=0x00, ins=0xD6, p1=0x00, p2=0x00, data=bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFF01'))

    # Zero out EF.EPSLOCI
    sc.transmit(cla=0x00, ins=0xA4, p1=0x00, p2=0x04, data=EF_EPSLOCI, le=0x00)
    sc.transmit(cla=0x00, ins=0xD6, p1=0x00, p2=0x00, data=bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF01'))


def send_terminal_profile():
    profile = bytearray(39)

    profile[0] = 0b00100000  # download: timer expiration
    profile[1] = 0b00000001  # other: command result
    profile[2] = 0b11101000  # proactive UICC: REFRESH, POLLING OFF, POLLING INTERVAL, MORE TIME
    profile[3] = 0b11000000  # proactive UICC: PROVIDE LOCAL INFORMATION for GERAN and E-UTRAN
    profile[4] = 0b00010001  # event-driven information: SET UP EVENT LIST
    profile[5] = 0b10011100  # event-driven information extensions: data available, channel status, access technology change, network search mode change
    profile[6] = 0b00000111  # multiple card proactive commands: power on card, power off card, perform card APDU
    profile[7] = 0b00000111  # proactive UICC: TIMER MANAGEMENT, PROVIDE LOCAL INFORMATION
    profile[8] = 0b10011100  # PROVIDE LOCAL INFORMATION for GERAN, PROVIDE LOCAL INFORMATION (access technology, language, timing advance)
    profile[9] = 0b00000000  # soft keys support: none
    profile[10] = 0b00000000  # soft keys information: none
    profile[11] = 0b11111111  # BIP proactive commands: OPEN CHANNEL, CLOSE CHANNEL, RECEIVE DATA, SEND DATA, GET CHANNEL STATUS, ...
    profile[12] = 0b11100011  # BIP supported bearers: 7 channels, GPRS bearer
    profile[13] = 0b01100000  # screen height: no display, no keypad
    profile[14] = 0b00000000  # screen width: none
    profile[15] = 0b00000000  # screen effects: none
    profile[16] = 0b11111111  # BIP supported bearers: TCP, UDP with UICC in client/server mode, HSDPA and E-UTRAN support
    profile[17] = 0b11010000  # PROVIDE LOCAL INFORMATION (search mode change, IMEISV, ESN)
    profile[18] = 0b00000000  # TIA/EIA-136-C: none
    profile[19] = 0b00000000  # 3GPP2 C.S0035-B CCAT: none
    profile[20] = 0b00000000  # extended launch browser capabilities: none
    profile[21] = 0b00000001  # UTRAN PS with extended parameters
    profile[22] = 0b01000000  # PROVIDE LOCAL INFORMATION (NMR (UTRAN/E-UTRAN/NG-RAN))
    profile[23] = 0b00000000  # class i: none
    profile[24] = 0b11010000  # multiple RATs supported in PROVIDE LOCAL INFORMATION, event network rejection
    profile[25] = 0b00000000  # event-driven information extensions: none
    profile[26] = 0b00000000  # event-driven information extensions: none
    profile[27] = 0b00000000  # text attributes: none
    profile[28] = 0b00000000  # text attributes: none
    profile[29] = 0b00010000  # ACTIVATE supported in REFRESH
    profile[30] = 0b00000000  # none
    profile[31] = 0b00000000  # none
    profile[32] = 0b10010111  # DNS server address can be requested, PROVIDE LOCAL INFORMATION (supported RATs), network access name reuse, support of refresh enforcement policy
    profile[33] = 0b00100000  # REFRESH with eUICC profile state change
    profile[34] = 0b00000110  # PDP event for data connection status change
    profile[35] = 0b00000001
    profile[36] = 0b00000100
    profile[37] = 0b00000000
    profile[38] = 0b00000000


    sc.transmit(cla=0x80, ins=0x10, p1=0x00, p2=0x00, data=profile)


def send_status():
    sc.transmit(cla=0x80, ins=0xF2, p1=0x01, p2=0xC)



def fetch():
    assert sc.refresh_needed is not None
    return sc.transmit(cla=0x80, ins=0x12, p1=0x00, p2=0x00, le=sc.refresh_needed)


async def show_exceptions(coro):
    try:
        await coro
    except asyncio.CancelledError:
        logger.debug('Task %s cancelled', coro)
    except BaseException as e:
        logger.error('Exception running %s:', coro, exc_info=e)
        raise e from None

class Timer:
    def __init__(self, timer_id, timer_val):
        self.timer_id = timer_id
        self.timer_value = timer_val
        self.start_time = None
        self.timer_initial_value = timer_val
        self.expired = False
        self.running = False
        self.task = None

    def start_timer(self):
        self.task = asyncio.create_task(show_exceptions(self.run_timer()), eager_start=True)

    @property
    def remaining_time(self):
        if self.expired:
            return 0

        if self.running:
            return max(0, self.timer_value - (time() - self.start_time))
        else:
            return self.timer_value

    async def run_timer(self):
        logger.info('Starting timer for %d seconds', self.timer_value)

        self.start_time = time()
        self.running = True
        try:
            await asyncio.sleep(self.timer_value)
        except asyncio.CancelledError:
            sleep_end = time()
            self.timer_value -= (sleep_end - self.start_time)
            self.running = False
            raise
        self.expired = True
        self.running = False
        logger.info('Sending ENVELOPE (TIMER EXPIRATION)')
        data = bytearray()
        data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC, cr=True)
        data += TimerIdentifier(identifier=self.timer_id, cr=True)
        data += TimerValue((0x00, 0x00, 0x00), cr=True)
        await send_timer_expiration(data)
        logger.debug('Event sent')

    def is_expired(self):
        return self.expired

    def stop_timer(self):
        if self.running:
            self.task.cancel()


def decode_timer_value(data):
    hex_data = data.hex()
    hours = int(f'{hex_data[1]}{hex_data[0]}')
    minutes = int(f'{hex_data[3]}{hex_data[2]}')
    seconds = int(f'{hex_data[5]}{hex_data[4]}')
    return seconds + 60 * minutes + 3600 * hours


def encode_timer_value(t):
    seconds = t % 60
    minutes = (t // 60) % 60
    hours = t // 3600

    return bytes.fromhex(str(hours).rjust(2, '0')[::-1] + str(minutes).rjust(2, '0')[::-1] + str(seconds).rjust(2, '0')[::-1])


async def send_with_retry(data: bytes):
    while True:
        try:
            sc.transmit(cla=0x80, ins=0xC2, p1=0x00, p2=0x00, data=data)
        except APDUException as e:
            if e.sw1 == 0x93 and e.sw2 == 0x00:
                await asyncio.sleep(1)
            else:
                raise e from None
        else:
            break

async def send_event(data: bytes):
    await send_with_retry(encode_tlv(b'\xD6', data))


async def send_timer_expiration(data: bytes):
    await send_with_retry(encode_tlv(b'\xD7', data))


class Channel:
    def __init__(self, channel_id, req_buffer_size=None, family=None, addr=None, proto=None, port=None):
        self.channel_id = channel_id
        self.addr = addr
        self.proto = proto
        self.send_buffer = bytearray()
        self.recv_buffer = bytearray()
        self.connected = False
        self.buffer_size = req_buffer_size
        self.port = port
        if family is not None and addr is not None and proto is not None and port is not None:
            self.socket = socket.socket(family=family, type=proto)
        else:
            self.socket = None
        self.task = None
        self.reader_task = None
        self.writer_task = None
        self.send_event: asyncio.Event | threading.Event = None

    def close(self):
        self.connected = False
        if self.socket is not None:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except OSError:
                pass
        if self.task is not None:
            self.task.cancel()

    def connect(self):
        ...

    def write(self, data: bytes, now: bool):
        ...

class UDPChannel(Channel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.read_event = asyncio.Event()
        self.cancel_event = threading.Event()
        self.read_lock = threading.Lock()
        self.send_event = asyncio.Event()
        self.datagrams = []

    def connect(self):
        assert self.socket is not None and self.addr is not None
        self.socket.connect((self.addr, self.port))
        self.connected = True
        self.task = asyncio.create_task(show_exceptions(self.run_task()))

    def write(self, data, now):
        if len(data) == 0 or not self.connected:
            return

        assert not self.send_event.is_set(), 'cannot send data while sending is still pending'
        self.send_buffer += data
        if now:
            self.send_event.set()

    async def run_task(self):
        self.reader_thread_task = asyncio.create_task(asyncio.to_thread(self.read_thread, asyncio.get_event_loop()))
        self.reader_task = asyncio.create_task(self.run_reader())
        self.writer_task = asyncio.create_task(self.run_writer())
        try:
            done, pending = await asyncio.wait((self.reader_thread_task, self.reader_task, self.writer_task), return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
        except asyncio.CancelledError:
            self.cancel_event.set()
            self.reader_task.cancel()
            self.writer_task.cancel()
            self.reader_thread_task.cancel()
            raise

    async def run_reader(self):
        while True:
            await self.read_event.wait()
            with self.read_lock:
                self.read_event.clear()
                datagram_length = len(self.datagrams[0])
            logger.info('Sending ENVELOPE (EVENT DOWNLOAD - Data available)')
            data = bytearray()
            data += EventList((Event.DATA_AVAILABLE,), cr=True)
            data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC, cr=True)
            data += ChannelStatus(status=self.channel_id | 0x80, extra=0x00, cr=True)  # TODO: check in the test spec
            data += ChannelDataLength(length=min(255, datagram_length), cr=True)
            await send_event(data)

    async def run_writer(self):
        while True:
            await self.send_event.wait()
            self.send_event.clear()
            logger.debug('Writing %d to socket', len(self.send_buffer))
            self.socket.send(self.send_buffer)
            self.send_buffer.clear()

    def read_thread(self, loop):
        while True:
            data = self.socket.recv(self.buffer_size)
            if data:
                with self.read_lock:
                    self.datagrams.append(data)
                    loop.call_soon_threadsafe(self.read_event.set)
            if self.cancel_event.is_set():
                break


class TCPChannel(Channel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.send_event = asyncio.Event()
        self.reader: asyncio.StreamReader|None = None
        self.writer: asyncio.StreamWriter|None = None
        self.reader_task = None
        self.writer_task = None
        self.reader: asyncio.StreamReader|None = None
        self.writer: asyncio.StreamWriter|None = None

    def close(self):
        self.connected = False
        if self.writer is not None:
            if not self.writer.is_closing():
                if self.writer.can_write_eof():
                    self.writer.write_eof()
                self.writer.close()
        if self.task is not None:
            self.task.cancel()

    def write(self, data, now):
        self.send_buffer += data
        if now:
            self.send_event.set()

    async def run_writer(self, writer):
        while True:
            await self.send_event.wait()
            self.send_event.clear()
            logger.debug('Writing %d to socket', len(self.send_buffer))
            writer.write(self.send_buffer)
            self.send_buffer.clear()
            await writer.drain()
            await asyncio.sleep(0)

    async def run_reader(self, reader):
        while (chunk := await reader.read(self.buffer_size)):
            self.recv_buffer += chunk
            # send the data to the card
            logger.info('Sending ENVELOPE (EVENT DOWNLOAD - Data available)')
            data = bytearray()
            data += EventList((Event.DATA_AVAILABLE,), cr=True)
            data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC, cr=True)
            data += ChannelStatus(status=self.channel_id | 0x80, extra=0x00, cr=True)  # TODO: check in the test spec
            data += ChannelDataLength(length=min(255, len(self.recv_buffer)), cr=True)
            await send_event(data)

        # TODO: wait for all the data to be read then send the event
        await asyncio.sleep(10)  # give an opportunity to process the proactive commands first

        # Send the channel closed event
        logger.info('Sending ENVELOPE (EVENT DOWNLOAD - Channel status)')
        data = bytearray()
        data += EventList((Event.CHANNEL_STATUS,), cr=True)
        data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC, cr=True)
        data += ChannelStatus(status=self.channel_id, extra=0x00, cr=True)  # TODO: check in the test spec
        await send_event(data)


    async def run_task(self):
        self.reader, self.writer = await asyncio.open_connection(sock=self.socket)
        self.reader_task = asyncio.create_task(self.run_reader(self.reader))
        self.writer_task = asyncio.create_task(self.run_writer(self.writer))
        try:
            done, pending = await asyncio.wait((self.reader_task, self.writer_task), return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
        except asyncio.CancelledError:
            self.reader_task.cancel()
            self.writer_task.cancel()
            self.close()
            raise

    def connect(self):
        assert self.socket is not None and self.addr is not None
        self.socket.connect((self.addr, self.port))
        self.socket.settimeout(0.5)
        self.connected = True
        self.task = asyncio.create_task(show_exceptions(self.run_task()), eager_start=True)


def close_all_tasks():
    global negotiated_poll_interval
    for i, channel in enumerate(channels):
        if channel is not None:
            channel.close()
            channels[i] = None
    for timer in timers.values():
        timer.stop_timer()
    timers.clear()
    requested_event_list.clear()
    negotiated_poll_interval = None

timers: dict[int, Timer] = {}
requested_event_list: list[int] = []
channels: list[Channel|None] = 7 * [None]

negotiated_poll_interval: int|None = None


class CommandDataNotUnderstood(Exception):
    pass


class CommandTypeNotUnderstood(Exception):
    pass


class CommandCannotBeProcessedCurrently(Exception):
    pass


class TagsDict(dict):
    def __getitem__(self, item):
        if isinstance(item, type) and issubclass(item, CTLV):
            return super().__getitem__(item.TAG)
        else:
            return super().__getitem__(item)

    def __contains__(self, item):
        if isinstance(item, type) and issubclass(item, CTLV):
            return super().__contains__(item.TAG)
        else:
            return super().__contains__(item)

    def __setitem__(self, key, value):
        if isinstance(key, type) and issubclass(key, CTLV):
            super().__setitem__(key.TAG, value)
        else:
            super().__setitem__(key, value)


card_reset_event = asyncio.Event()


def process_proactive_command(ret: bytes):
    global negotiated_poll_interval
    global requested_event_list

    i, tag, tag_class, constructed, tag_number = parse_tag(ret, 0)
    assert tag == b'\xd0'
    i, length = parse_length(ret, i)
    tags: TagsDict = TagsDict()
    while i < len(ret):
        i, cr, tag = parse_comprehension_tlv_tag(ret, i)
        i, length = parse_length(ret, i)
        data = ret[i:i+length]
        i += length
        logger.debug(f'C-TLV tag {tag.hex()} (CR={cr}): {data.hex()}')
        parsed_tag = CTLV.parse(tag, cr, data)
        if tag in tags:
            if isinstance(tags[tag], list):
                tags[tag].append(parsed_tag)
            else:
                tags[tag] = [tags[tag], parsed_tag]
        else:
            tags[tag] = parsed_tag
    try:
        match tags[CommandDetails].command:
            case Command.POLL_INTERVAL:
                assert Duration in tags
                unit = tags[Duration].unit
                if unit == 0x00:
                    mult = 60.0
                elif unit == 0x01:
                    mult = 1.0
                elif unit == 0x02:
                    mult = 0.1
                else:
                    raise ValueError(f'Invalid duration unit {unit}')
                poll_interval_requested = int(tags[Duration].interval * mult)
                poll_interval_raw = tags[Duration].interval
                poll_interval_unit = tags[Duration].unit

                logger.info('processing POLL INTERVAL, requested interval %d s', poll_interval_requested)
                negotiated_poll_interval = poll_interval_requested

                # Construct the response
                data = bytearray()
                data += tags[CommandDetails]
                data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)  # device identities: terminal to UICC
                data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY) # result: success
                data += Duration(unit=poll_interval_unit, interval=poll_interval_raw) # duration
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.SET_UP_EVENT_LIST:
                logger.info('processing SET UP EVENT LIST')
                requested_event_list = [*tags[EventList].data]
                data = bytearray()
                data += tags[CommandDetails]
                data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.PROVIDE_LOCAL_INFORMATION:
                logger.info('processing PROVIDE LOCAL INFORMATION (%s)', f'{tags[CommandDetails].command_data:02X}')
                match tags[CommandDetails].command_data:
                    case 0x00:  # location information
                        # LTE
                        data = bytearray()
                        data += tags[CommandDetails]
                        data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                        if network_type is NetworkType.eutran:
                            data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                            data += LocalInformation(location.mcc_mnc + bytes.fromhex(location.tac) + location.eci)  # E-UTRAN
                        else:
                            data += Result(result=ResultCode.TERMINAL_CURRENTLY_UNABLE_TO_PROCESS_COMMAND, extra=ResultExtra.NO_SERVICE)
                        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                    case 0x01:  # IMEI
                        data = bytearray()
                        data += tags[CommandDetails]
                        data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                        data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                        imei_array = bytearray.fromhex(('A' + imei).ljust(16, 'F'))
                        for i in range(len(imei_array)):
                            imei_array[i] = ((imei_array[i] & 0xF0) >> 4) | ((imei_array[i] & 0x0F) << 4)

                        data += Imei(imei_array)
                        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                    case info_type:
                        logger.warning(f'Unknown local information type {info_type:02X}')
                        data = bytearray()
                        data += tags[CommandDetails]
                        data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                        data += Result(result=ResultCode.COMMAND_DATA_NOT_UNDERSTOOD_BY_TERMINAL)
                        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.TIMER_MANAGEMENT:
                logger.info('processing TIMER MANAGEMENT (%s)', f'{tags[CommandDetails].command_data:02X}')
                timer_id = tags[TimerIdentifier].identifier
                match tags[CommandDetails].command_data:
                    case 0:  # start
                        value = decode_timer_value(tags[TimerValue].data)
                        timers[timer_id] = Timer(timer_id, value)
                        timers[timer_id].start_timer()
                        data = bytearray()
                        data += tags[CommandDetails]
                        data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                        data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)

                    case 1:  # deactivate
                        if timers[timer_id].running:
                            timers[timer_id].stop_timer()
                            remaining_time = encode_timer_value(timers[timer_id].remaining_time)
                            data = bytearray()
                            data += tags[CommandDetails]
                            data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                            data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                            data += TimerValue(remaining_time)
                            sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                        else:
                            data = bytearray()
                            data += tags[CommandDetails]
                            data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                            data += Result(result=ResultCode.ACTION_IN_CONTRADICTION_WITH_THE_CURRENT_TIMER_STATE)
                            sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                    case 2:  # get current value
                        if timers[timer_id].running:
                            remaining_time = encode_timer_value(timers[timer_id].remaining_time)
                            data = bytearray()
                            data += tags[CommandDetails]
                            data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                            data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                            data += TimerValue(remaining_time)
                            sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                        else:
                            data = bytearray()
                            data += tags[CommandDetails]
                            data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                            data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                            sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                    case cmd:
                        logger.warning(f'Unknown timer management command {cmd:02X}')
                        data = bytearray()
                        data += tags[CommandDetails]
                        data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                        data += Result(result=ResultCode.COMMAND_DATA_NOT_UNDERSTOOD_BY_TERMINAL)
                        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.OPEN_CHANNEL:
                logger.info('processing OPEN CHANNEL')

                port = None
                proto = None
                req_buffer_size = 1500
                dns_requested = tags[CommandDetails].command_data & 0x08 != 0
                connection_required = tags[CommandDetails].command_data & 0x01 != 0
                ip_addr = None
                family = None

                if InterfaceTransportLevel in tags:
                    transport = tags[InterfaceTransportLevel]
                    port = transport.port
                    match transport.protocol:
                        case 0x01:
                            logger.info('UDP connection requested to port %d', port)
                            proto = socket.SOCK_DGRAM
                        case 0x02:
                            logger.info('TCP connection requested to port %d', port)
                            proto = socket.SOCK_STREAM
                        case v:
                            logger.warning(f'Unknown value {v:02X} for transport type')
                            raise CommandDataNotUnderstood()

                if BufferSize in tags:
                    req_buffer_size = tags[BufferSize].size

                if OtherAddress in tags:
                    match tags[OtherAddress].address_type:
                        case 0x21:
                            ip_addr = socket.inet_ntop(socket.AF_INET, tags[OtherAddress].address)
                            family = socket.AF_INET
                        case 0x57:
                            ip_addr = socket.inet_ntop(socket.AF_INET6, tags[OtherAddress].address)
                            family = socket.AF_INET6
                        case v:
                            logger.warning(f'Invalid address type {v:02x}')
                            raise CommandDataNotUnderstood()
                for i, channel in enumerate(channels):
                    if channel is None:
                        break
                else:
                    logger.warning('All channels are occupied')
                    raise CommandDataNotUnderstood()
                channel_number = i+1
                channel_class = TCPChannel if proto == socket.SOCK_STREAM else UDPChannel
                new_channel = channel_class(channel_number, req_buffer_size, family, ip_addr, proto, port)
                channels[i] = new_channel

                if connection_required and ip_addr is not None:
                    new_channel.connect()

                data = bytearray()
                data += tags[CommandDetails]
                data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)

                # add channel status: link established
                link_status = 0x80 if connection_required and ip_addr is not None else 0x00
                data += ChannelStatus(status=channel_number | link_status, extra=0x00)

                # bearer description
                data += BearerDescription(bearer_type=0x03)  # default bearer for requested transport layer

                # add buffer size
                data += BufferSize(size=req_buffer_size)

                # DNS server address
                if dns_requested:
                    logger.info('SIM is requesting DNS server address')
                    data += DnsServerAddress(address_type=0x21, address=b'\x01\x01\x01\x01')

                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.CLOSE_CHANNEL:
                logger.info('Processing CLOSE CHANNEL')
                assert DeviceIdentity.CHANNEL + 1 <= tags[DeviceIdentities].destination <= DeviceIdentity.CHANNEL + 7
                channel_number = tags[DeviceIdentities].destination - DeviceIdentity.CHANNEL
                if channels[channel_number - 1] is not None:
                    channels[channel_number - 1].close()
                    channels[channel_number - 1] = None

                data = bytearray()
                data += tags[CommandDetails]
                data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.SEND_DATA:
                logger.info('Got SEND DATA command')
                assert DeviceIdentity.CHANNEL + 1 <= tags[DeviceIdentities].destination <= DeviceIdentity.CHANNEL + 7
                channel_id = tags[DeviceIdentities].destination - DeviceIdentity.CHANNEL
                channel = channels[channel_id - 1]
                if channel is None:
                    raise CommandDataNotUnderstood()
                logger.debug('calling write')
                channel.write(tags[ChannelData].data, tags[CommandDetails].command_data & 0x01)
                data = bytearray()
                data += tags[CommandDetails]
                data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.RECEIVE_DATA:
                logger.info('Got RECEIVE DATA command')
                assert DeviceIdentity.CHANNEL + 1 <= tags[DeviceIdentities].destination <= DeviceIdentity.CHANNEL + 7
                channel_id = tags[DeviceIdentities].destination - DeviceIdentity.CHANNEL
                channel = channels[channel_id - 1]
                if channel is None:
                    raise CommandDataNotUnderstood()
                if isinstance(channel, UDPChannel):
                    requested_length = tags[ChannelDataLength].length
                    with channel.read_lock:
                        if not channel.datagrams:
                            # nothing yet, the card is too eager
                            raise CommandCannotBeProcessedCurrently()
                        to_send = channel.datagrams[0][:requested_length]
                        if len(channel.datagrams[0]) == requested_length:
                            channel.datagrams.pop(0)
                            remaining = 0
                        else:
                            remaining = len(channel.datagrams[0]) - requested_length
                            channel.datagrams[0] = channel.datagrams[0][requested_length:]
                else:
                    requested_length = tags[ChannelDataLength].length
                    to_send = channel.recv_buffer[:requested_length]
                    remaining = len(channel.recv_buffer) - requested_length
                    channel.recv_buffer = channel.recv_buffer[requested_length:]
                logger.debug('remaining length: %d', remaining)
                data = bytearray()
                data += tags[CommandDetails]
                data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                data += ChannelData(to_send)
                data += ChannelDataLength(bytes((min(255, remaining),)))
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.REFRESH:
                logger.info('Processing REFRESH (%s)', f'{tags[CommandDetails].command_data:02X}')
                if tags[CommandDetails].command_data in (0x04, 0x09):
                    if tags[CommandDetails].command_data == 0x04:
                        logger.info('UICC reset requested')
                    else:
                        logger.info('eUICC Profile State Change')
                    card_reset_event.set()
                    data = bytearray()
                    data += tags[CommandDetails]
                    data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                    data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                    sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                else:
                    raise CommandDataNotUnderstood()
            case Command.SET_UP_MENU:
                logger.info('Processing SET UP MENU')
                data = bytearray()
                data += tags[CommandDetails]
                data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
                data += Result(result=ResultCode.COMMAND_PERFORMED_SUCCESSFULLY)
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)

            case cmd:
                logger.warning(f'Unhandled proactive command {Command(cmd).name}')
                raise CommandTypeNotUnderstood()
    except CommandDataNotUnderstood:
        data = bytearray()
        data += tags[CommandDetails]
        data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
        data += Result(result=ResultCode.COMMAND_DATA_NOT_UNDERSTOOD_BY_TERMINAL)
        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
    except CommandTypeNotUnderstood:
        data = bytearray()
        data += tags[CommandDetails]
        data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
        data += Result(result=ResultCode.COMMAND_TYPE_NOT_UNDERSTOOD_BY_TERMINAL)
        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
    except CommandCannotBeProcessedCurrently:
        data = bytearray()
        data += tags[CommandDetails]
        data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC)
        data += Result(result=ResultCode.TERMINAL_CURRENTLY_UNABLE_TO_PROCESS_COMMAND, extra=0x00)  # no specific cause can be given
        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)

waiting_for_refresh = asyncio.Event()

async def do_refresh():
    while True:
        while sc.refresh_needed is not None:
            logger.debug('Processing proactive command')
            process_proactive_command(fetch())
            await asyncio.sleep(0)
        waiting_for_refresh.set()
        await refresh_event.wait()
        waiting_for_refresh.clear()


async def poll():
    logger.info('Starting polling coroutine')
    assert negotiated_poll_interval is not None
    while True:
        await asyncio.sleep(negotiated_poll_interval)
        if sc.refresh_needed is None:
            send_status()


def force_polling(cla):
    logger.info('Forcing polling')
    try:
        sc.transmit(cla=cla, ins=0x00, p1=0x00, p2=0x00, data=bytes.fromhex('400101'))
    except APDUException as e:
        logger.warning('Cannot force polling:', exc_info=e)
        return False
    else:
        return True


max_command_data = 255


def open_logical_channel() -> int:
    ret = sc.transmit(cla=0x00, ins=0x70, p1=0x00, p2=0x00, le=0x00)
    channel = ret[0]
    if channel < 4:
        cla = channel
    elif channel < 20:
        cla = 0x40 | (channel - 4)
    else:
        raise ValueError('Invalid logical channel number')
    return cla

has_iot_specific_metadata_support = False
euicc_categories = ['other', 'basicEuicc', 'mediumEuicc', 'contactlessEuicc']
ipa_modes = ['IPAd', 'IPAe']

def get_euicc_info(cla):
    """
    ISD-R must be selected
    """

    global has_iot_specific_metadata_support

    tags = parse_tags(es10x(sc, cla, bytes.fromhex('BF3E035C015A'), max_command_data=max_command_data))
    eid = tags[b'\xbf\x3e'][0][b'\x5a'][0].hex().upper()
    logger.info('EID: %s', eid)

    tags = parse_tags(es10x(sc, cla, bytes.fromhex('BF2200'), max_command_data=max_command_data))[b'\xbf\x22'][0]
    profile_version = '.'.join(map(str, tags[b'\x81'][0]))
    sgp22_version = '.'.join(map(str, tags[b'\x82'][0]))
    fw_version = '.'.join(map(str, tags[b'\x83'][0]))
    global_platform_version = '.'.join(map(str, tags[b'\x87'][0])) if b'\x87' in tags else None
    ts102241_version = '.'.join(map(str, tags[b'\x86'][0])) if b'\x86' in tags else None
    category = euicc_categories[tags[b'\x8B'][0][0]] if b'\x8B' in tags else None
    pp_version = '.'.join(map(str, tags[b'\x04'][0]))
    sas_accreditation_number = tags[b'\x0C'][0].decode('utf-8')
    rsp_capabilities_raw = tags[b'\x88'][0]

    unused_bits = rsp_capabilities_raw[0]
    bitstring = '{:b}'.format(int.from_bytes(rsp_capabilities_raw[1:], byteorder='big') >> unused_bits).ljust(29, '0')

    if is_sgp32:
        ipa_mode = ipa_modes[tags[b'\x90'][0][0]]
        sgp32_version = ', '.join('.'.join(map(str, ver)) for ver in tags[b'\xb4'][0][b'\xa0'][0][b'\x04'])
        ecall_supported = b'\x81' in tags[b'\xb4'][0]
        fallback_supported = b'\x82' in tags[b'\xb4'][0]
        fallback_allowed_update_supported = b'\x83' in tags[b'\xb4'][0]

    logger.info('SGP.22 version: %s', sgp22_version)
    logger.info('Base eUICC Profile package version: %s', profile_version)
    logger.info('eUICC firmware version: %s', fw_version)
    logger.info('ETSI TS 102 241 (UICC API for JavaCard) version: %s', ts102241_version)
    logger.info('GlobalPlatform version: %s', global_platform_version)
    logger.info('eUICC category: %s', category)
    logger.info('Profile protection version: %s', pp_version)
    logger.info('SAS accreditation number: %s', sas_accreditation_number)
    if is_sgp32:
        logger.info('SGP.32 version: %s', sgp32_version)
        logger.info('Emergency call supported: %s', ecall_supported)
        logger.info('Fallback mechanism supported: %s', fallback_supported)
        logger.info('Support for update of the Fallback Allowed metadata via ES6: %s', fallback_allowed_update_supported)

    logger.info('At least one more profile can be installed: %s', bitstring[0])
    logger.info('CRL support: %s', bitstring[1])
    logger.info('Remote profile management support: %s', bitstring[2])
    logger.info('Test profile support: %s', bitstring[3])
    logger.info('Support for ASN.1 extensibility in the Device Info: %s', bitstring[4])
    logger.info('Support for Service Specific Data in the Profile Metadata: %s', bitstring[5])
    logger.info('Support for eUICC OS Update: %s', bitstring[19])
    logger.info('Support for SGP.32 iotSpecificMetadata and iotSpecificProfileInfo: %s', bitstring[26])
    logger.info('Support for eUICC Minimum Security Level Check: %s', bitstring[27])
    logger.info('Support for RSP Server Test Profile Allow-list Check: %s', bitstring[28])

    has_iot_specific_metadata_support = bitstring[26] == '1'

def enable_ipae(cla):
    """
    ISD-R must be selected
    """
    tags = parse_tags(es10x(sc, cla, bytes.fromhex('BF420480020780'), max_command_data=max_command_data))
    if tags[b'\xbf\x42'][0][b'\x80'][0] != b'\x00':
        logger.error('IPAe activation failed')
        sys.exit(1)
    else:
        logger.info('IPAe activation successful')


def select_isd_r(cla) -> tuple[bool, bool]:
    global max_command_data
    ISD_R_AID = bytes.fromhex('A0000005591010FFFFFFFF8900000100')
    fci = parse_tags(sc.transmit(cla=cla, ins=0xA4, p1=0x04, p2=0x00, data=ISD_R_AID, le=0))

    sgp22 = b'\xE0' in fci[b'\x6F'][0]
    sgp32 = b'\xE1' in fci[b'\x6F'][0]

    if not sgp22:
        logger.warning('No SGP.22 support')
    else:
        logger.info('SGP.22 eUICC')
        sgp22_version = '.'.join(map(str, fci[b'\x6F'][0][b'\xE0'][0][b'\x82'][0]))
        logger.info('SGP.22 version: %s', sgp22_version)
        bitstring = fci[b'\x6F'][0][b'\xE0'][0][b'\x80'][0] if b'\x80' in fci[b'\x6F'][0][b'\xE0'][0] else b'\x00\x00'
        unused_bits = bitstring[0]
        value = int.from_bytes(bitstring[1:], byteorder='big') >> unused_bits
        value = f'{value:b}'.ljust(2, '0')
        lpae_cat_supported = value[0] == '1'
        lpae_scws_supported = value[1] == '1'
        logger.info('LPAe using CAT supported: %s', lpae_cat_supported)
        logger.info('LPAe using SCWS supported: %s', lpae_scws_supported)

    if not sgp32:
        logger.warning('No SGP.32 support')
        max_command_data = 255
    else:
        logger.info('SGP.32 eUICC')
        max_command_data = int.from_bytes(fci[b'\x6f'][0][b'\xa5'][0][b'\x9f\x65'][0], byteorder='big')

        bitstring = fci[b'\x6F'][0][b'\xE1'][0][b'\x80'][0]
        unused_bits = bitstring[0]
        value = int.from_bytes(bitstring[1:], byteorder='big') >> unused_bits
        value = f'{value:b}'.ljust(2, '0')
        ipae_supported = value[0] == '1'
        profile_enabled = value[1] == '1'
        logger.info('IPAe supported: %s', ipae_supported)
        logger.info('Profile enabled: %s', profile_enabled)

    return sgp22, sgp32


def get_ipae_version(cla):
    ipae_version = sc.transmit(cla=cla|0x80, ins=0xCA, p1=0x00, p2=0x01, le=0x00)
    logger.info('IPAe version: %s', '.'.join(map(str, ipae_version)))


def select_ipae(cla):
    IPAE_AID = bytes.fromhex('A00000084455F1279166010101')
    sc.transmit(cla=cla, ins=0xA4, p1=0x04, p2=0x0C, data=IPAE_AID)


def send_terminal_capability():
    data = bytearray()
    data += encode_tlv(b'\x83', b'\x0F')  # SGP.22 LPAd supported, LUIe based on SCWS supported
    data += encode_tlv(b'\x84', b'\x01')  # SGP.32 IPAd supported
    sc.transmit(cla=0x80, ins=0xAA, p1=0x00, p2=0x00, data=encode_tlv(b'\xA9', data))


def parse_iccid(iccid: bytes) -> str:
    return ''.join(f'{x:02X}'[::-1] for x in iccid).rstrip('F')


result_codes = {0: 'ok', 1: 'ICCID not found', 2: 'Profile not in disabled state', 3: 'Disallowed by policy',
                4: 'Wrong profile re-enabling', 5: 'CAT busy', 127: 'undefined error'}

def switch_profile(cla: int, iccid: bytes):
    data = bytearray()
    data += encode_tlv(b'\xA0', encode_tlv(b'\x5A', iccid))
    data += encode_tlv(b'\x81', b'\xFF')  # refreshFlag
    data = encode_tlv(b'\xBF\x31', data)
    result = parse_tags(es10x(sc, cla, data, max_command_data=max_command_data))

    result_code = int.from_bytes(result[b'\xBF\x31'][0][b'\x80'][0], byteorder='big', signed=True)

    if result_code == 0:
        logger.info('Profile switch successful')
        return True
    else:
        logger.error('Profile switch failed: %s', result_codes.get(result_code, 'Invalid result code'))
        return False


def get_efdir():
    """
    MF must be selected
    """
    fcp = parse_tags(sc.transmit(cla=0x00, ins=0xA4, p1=0x00, p2=0x04, data=b'\x2F\x00', le=0))
    efdir_file_size = int.from_bytes(fcp[b'\x62'][0][b'\x80'][0], byteorder='big')
    efdir_record_size = int.from_bytes(fcp[b'\x62'][0][b'\x82'][0][2:4], byteorder='big')
    efdir_num_records = fcp[b'\x62'][0][b'\x82'][0][4]
    logger.debug('EF.DIR file size: %d', efdir_file_size)
    logger.debug('EF.DIR record size: %d', efdir_record_size)
    logger.debug('EF.DIR number of records: %d', efdir_num_records)

    efdir = []
    # Read the records
    for i in range(efdir_num_records):
        record = parse_tags(sc.transmit(cla=0x00, ins=0xB2, p1=(i + 1), p2=0x04, le=efdir_record_size),
                            break_on_ff=True)
        if record:
            efdir.append(record)

    return efdir


def get_usim_aid() -> bytes|None:
    efdir = get_efdir()

    logger.debug('Found %s records in EF.DIR', len(efdir))
    for record in efdir:
        aid = record[b'\x61'][0][b'\x4f'][0]
        if aid.startswith(bytes.fromhex('A00000008710')):
            logger.debug('USIM AID: %s', aid.hex().upper())
            return aid
    return None


def get_pin_attempts(pin_ref):
    try:
        sc.transmit(cla=0x00, ins=0x20, p1=0x00, p2=pin_ref)
    except APDUException as e:
        if e.sw1 == 0x63 and e.sw2 & 0xF0 == 0xC0:
            return e.sw2 & 0x0F
        else:
            raise e from None
    else:
        raise RuntimeError('VERIFY PIN with empty data did not return an error code')


@dataclass
class Profile:
    iccid_raw: bytes
    service_provider_name: str|None
    profile_name: str|None
    enabled: bool

    @property
    def iccid(self):
        return parse_iccid(self.iccid_raw)


profiles = []
profile_states = ['disabled', 'enabled']
profile_classes = ['test', 'provisioning', 'operational']
notification_event_names = ['install', 'enable', 'disable', 'delete']


def get_profiles(cla: int):
    tag_list = bytearray()
    tag_list += b'\x5A'      # ICCID
    tag_list += b'\x4F'      # ISD-P AID
    tag_list += b'\x9F\x70'  # Profile state
    tag_list += b'\x90'      # Profile nickname
    tag_list += b'\x91'      # Service provider name
    tag_list += b'\x92'      # Profile name
    tag_list += b'\x95'      # Profile class
    tag_list += b'\xB6'      # Notification configuration info
    tag_list += b'\xB7'      # Profile owner

    request = encode_tlv(b'\xBF\x2D', encode_tlv(b'\x5C', tag_list))
    result = es10x(sc, cla_isdr, request, max_command_data=max_command_data)
    profile_data = parse_tags(result)

    profiles.clear()

    if not profile_data[b'\xbf\x2d'][0][b'\xa0'][0]:
        logger.warning('No profiles installed')
    else:
        for i, profile in enumerate(profile_data[b'\xbf\x2d'][0][b'\xa0'][0][b'\xe3'], start=1):
            service_provider_name = profile[b'\x91'][0].decode('utf-8', errors='replace') if b'\x91' in profile else None
            profile_name = profile[b'\x92'][0].decode('utf-8', errors='replace') if b'\x92' in profile else None
            profile_nickname = (profile[b'\x90'][0].partition(b'\x00')[0]).decode('utf-8', errors='replace') if b'\x90' in profile else None
            iccid_raw = profile[b'\x5A'][0]
            iccid = parse_iccid(iccid_raw)
            isdp_aid = profile[b'\x4F'][0].hex().upper()
            profile_state = profile_states[int.from_bytes(profile[b'\x9F\x70'][0], byteorder='big', signed=True)]
            profile_class = profile_classes[int.from_bytes(profile[b'\x95'][0], byteorder='big', signed=True)]
            sm_dp_plus_server = None
            notification_events = None
            profile_owner = None

            if b'\xB6' in profile:
                notification_event_raw = profile[b'\xB6'][0][b'\x30'][0][b'\x80'][0]
                unused_bits = notification_event_raw[0]
                notification_event_bitstring = '{:b}'.format(int.from_bytes(notification_event_raw[1:], byteorder='big') >> unused_bits).ljust(4, '0')
                notification_events_list = []
                for j in range(4):
                    if notification_event_bitstring[i] == '1':
                        notification_events_list.append(notification_event_names[j])
                notification_events = ', '.join(notification_events_list)
                sm_dp_plus_server = profile[b'\xB6'][0][b'\x30'][0][b'\x81'][0].decode('utf-8')

            if b'\xB7' in profile:
                mcc_mnc = profile[b'\xB7'][0][b'\x80'][0].hex().upper()
                mcc = mcc_mnc[1] + mcc_mnc[0] + mcc_mnc[3]
                mnc = mcc_mnc[5] + mcc_mnc[4] + mcc_mnc[2]

                profile_owner = mcc.rstrip('F') + ' '  + mnc.rstrip('F')

            profiles.append(Profile(iccid_raw=iccid_raw, service_provider_name=service_provider_name, profile_name=profile_name,
                                    enabled=profile_state == 'enabled'))

            logger.info('Profile %d:', i)
            logger.info('\tService provider name: %s', service_provider_name)
            logger.info('\tProfile name: %s', profile_name)
            logger.info('\tProfile nickname: %s', profile_nickname)
            logger.info('\tProfile owner: %s', profile_owner)
            logger.info('\tICCID: %s', iccid)
            logger.info('\tISD-P AID: %s', isdp_aid)
            logger.info('\tProfile state: %s', profile_state)
            logger.info('\tProfile class: %s', profile_class)
            logger.info('\tNotification events: %s', notification_events)
            logger.info('\tNotification SM-DP+ server: %s', sm_dp_plus_server)


PGUP_PGDOWN_LINES = 10
SCROLLBACK = 2000
PROMPT_LINES = 6

cli_line: str|None = None
cli_line_processed_event = threading.Event()
cli_line_available_event = asyncio.Event()
is_thales: bool = False
last_line: int = 0
currently_scrolling: bool = False

def move_up_by(n: int):
    global pad_scroll, currently_scrolling
    cursor = editscreen.getyx()
    pad_scroll = max(0, pad_scroll - n)
    if not (pad_scroll == last_line - (curses.LINES - PROMPT_LINES - 1) or last_line < curses.LINES - PROMPT_LINES - 1):
        main_window.addstr(curses.LINES - PROMPT_LINES - 1, 1, f' scrolling ')
        main_window.noutrefresh()
        currently_scrolling = True
    editscreen.move(*cursor)
    flush_screen()


def move_down_by(n: int):
    global pad_scroll, currently_scrolling
    cursor = editscreen.getyx()
    pad_scroll = min(last_line - (curses.LINES - PROMPT_LINES - 1), pad_scroll + n)
    if pad_scroll == last_line - (curses.LINES - PROMPT_LINES - 1) or last_line < curses.LINES - PROMPT_LINES - 1:
        main_window.hline(curses.LINES - PROMPT_LINES - 1, 0, curses.ACS_HLINE, curses.COLS)
        main_window.noutrefresh()
        currently_scrolling = False

    editscreen.move(*cursor)
    flush_screen()


def validate(ch: int|str):
    global pad_scroll, currently_scrolling
    if ch == curses.KEY_PPAGE:
        move_up_by(PGUP_PGDOWN_LINES)
        return None
    elif ch == curses.KEY_NPAGE:
        move_down_by(PGUP_PGDOWN_LINES)
        return None
    elif ch == curses.KEY_UP:
        move_up_by(1)
        return None
    elif ch == curses.KEY_DOWN:
        move_down_by(1)
        return None
    else:
        return ch


def cli_input_thread(loop: asyncio.AbstractEventLoop):
    global cli_line
    while True:
        cli_line = textinput.edit(validate=validate)
        if cli_line.strip() == 'exit':
            return
        editscreen.move(0, 0)
        editscreen.clear()
        editscreen.refresh()
        loop.call_soon_threadsafe(cli_line_available_event.set)
        cli_line_processed_event.wait()
        cli_line_processed_event.clear()


# TODO: add lock for the screen
def flush_screen():
    screen.noutrefresh(pad_scroll, 0, 0, 0, curses.LINES - PROMPT_LINES - 2, curses.COLS)
    editscreen.noutrefresh()
    curses.doupdate()


def print_screen(*args, end='\n', flush=True):
    global last_line, pad_scroll
    assert screen is not None
    cursor = editscreen.getyx()
    screen.addstr(' '.join(map(str, args)) + end)
    coords = screen.getyx()
    last_line = coords[0]
    if not currently_scrolling and last_line >= curses.LINES - PROMPT_LINES - 1:
        pad_scroll = last_line - (curses.LINES - PROMPT_LINES - 1)
    editscreen.move(*cursor)

    if flush:
        flush_screen()


class CLIArgumentParser(argparse.ArgumentParser):
    def exit(self, status: int = 0, message: str | None = None):
        if message is not None:
            print_screen(message)
        sys.exit(status)

    @staticmethod
    def error(message):
        print_screen(message)
        sys.exit(2)

    def print_help(self, file = None) -> None:
        print_screen(self.format_help(), end='')


async def cli():
    global network_type, profile_switch_requested, profile_state_changed, network_reject_scheduled

    cli_parser = CLIArgumentParser(prog='', description='Modem emulator', exit_on_error=False, add_help=False, color=False)
    subparsers = cli_parser.add_subparsers(dest='command')
    exit_parser = subparsers.add_parser('exit', exit_on_error=False, color=False, help='Exit the program')
    help_parser = subparsers.add_parser('help', exit_on_error=False, color=False, help='Get this message')
    reset_parser = subparsers.add_parser('reset', exit_on_error=False, color=False, help='Reset the UICC')
    profile_parser = subparsers.add_parser('profile', exit_on_error=False, color=False, help='Manage eUICC profiles')

    profile_subparsers = profile_parser.add_subparsers(dest='profile_command')
    profile_subparsers.add_parser('list', exit_on_error=False, color=False, help='List installed profiles')
    switch_parser = profile_subparsers.add_parser('switch', exit_on_error=False, color=False, help='Switch the activated profile')
    switch_parser.add_argument('iccid', metavar='ICCID', help='The ICCID of the profile to switch to')

    network_parser = subparsers.add_parser('network', exit_on_error=False, color=False, help='Manage the network')
    poll_parser = subparsers.add_parser('poll', help='Force polling on a Thales eUICC', exit_on_error=False, color=False)
    network_subparsers = network_parser.add_subparsers(dest='network_command')
    disconnect_parser = network_subparsers.add_parser('disconnect', exit_on_error=False, color=False, help='Disconnect from the network')
    reject_parser = network_subparsers.add_parser('reject', exit_on_error=False, color=False, help='Send or schedule a network rejection event')
    reject_parser.add_argument('--after-profile-state-change', action='store_true', help='Schedule the network rejection after a profile state change')
    connect_parser = network_subparsers.add_parser('connect', exit_on_error=False, color=False, help='Connect to the network')
    status_parser = network_subparsers.add_parser('status', exit_on_error=False, color=False, help='Get the current network status')
    while True:
        await cli_line_available_event.wait()
        cli_line_available_event.clear()
        assert cli_line is not None
        try:
            args = cli_parser.parse_args(shlex.split(cli_line))
        except (argparse.ArgumentError, argparse.ArgumentTypeError) as e:
            print_screen(e)
        except SystemExit:
            pass  # help was printed
        else:
            match args.command:
                case 'profile':
                    match args.profile_command:
                        case 'list':
                            print_screen('Note: reset the eUICC to re-read the list of profiles as it might have changed since then')
                            for i, profile in enumerate(profiles, start=1):
                                print_screen('Profile', i)
                                print_screen('\tICCID:', profile.iccid)
                                print_screen('\tService provider name:', profile.service_provider_name)
                                print_screen('\tProfile name:', profile.profile_name)
                                print_screen('\tProfile enabled:', profile.enabled)
                        case 'switch':
                            for profile in profiles:
                                if profile.iccid == args.iccid:
                                    profile_switch_requested = profile.iccid_raw
                                    card_reset_event.set()
                                    break
                            else:
                                print_screen('Error: profile', args.iccid, 'not found')
                case 'reset':
                    print_screen('Resetting the card')
                    card_reset_event.set()
                case 'help':
                    print_screen(cli_parser.format_help(), end='')
                case 'exit':
                    return
                case 'network':
                    match args.network_command:
                        case 'reject':
                            if args.after_profile_state_change:
                                logger.info('Scheduling a network rejection event after a profile state change')
                                network_reject_scheduled = True
                            else:
                                print_screen('Not implemented')
                        case 'status':
                            if network_type is not NetworkType.disconnected:
                                print_screen('Connected to the network, network type', network_friendly_names[network_type])
                            else:
                                print_screen('Disconnected from the network')
                            print_screen('IMEI:', imei)
                            if network_type is NetworkType.eutran:
                                print_screen('Operator:', location.mcc, location.mnc)
                        case 'disconnect':
                            if network_type is NetworkType.disconnected:
                                print_screen('Already disconnected')
                            else:
                                print_screen('Disconnecting from network')
                                await waiting_for_refresh.wait()
                                network_type = NetworkType.disconnected
                                update_location_no_service()
                                if Event.LOCATION_STATUS in requested_event_list:
                                    logger.info('Sending ENVELOPE (EVENT DOWNLOAD - Location status)')
                                    data = bytearray()
                                    data += EventList((Event.LOCATION_STATUS,), cr=True)
                                    data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC, cr=True)
                                    data += LocationStatus(status=0x02, cr=True)  # No service
                                    await send_event(data)
                                else:
                                    logger.warning('SIM did not set up Location status in the event list')
                        case 'connect':
                            if network_type is not NetworkType.disconnected:
                                print_screen('Already connected')
                            else:
                                print_screen('Connecting to network')
                                await waiting_for_refresh.wait()
                                network_type = NetworkType.eutran
                                update_location_eutran(location)
                                if Event.LOCATION_STATUS in requested_event_list:
                                    logger.info('Sending ENVELOPE (EVENT DOWNLOAD - Location status)')
                                    data = bytearray()
                                    data += EventList((Event.LOCATION_STATUS,), cr=True)
                                    data += DeviceIdentities(source=DeviceIdentity.TERMINAL, destination=DeviceIdentity.UICC, cr=True)
                                    data += LocationStatus(status=0x00, cr=True)  # Service available
                                    data += LocalInformation(location.mcc_mnc + bytes.fromhex(location.tac) + location.eci, cr=True)  # E-UTRAN
                                    await send_event(data)
                                else:
                                    logger.warning('SIM did not set up Location status in the event list')
                case 'poll':
                    if not is_thales:
                        print_screen('Not a Thales eUICC')
                    else:
                        if force_polling(cla_ipae):
                            print_screen('Force polling success')
                        else:
                            print_screen('Force polling failed; APDU polling is disabled or the IPAe is busy')

        cli_line_processed_event.set()

cla_ipae: int|None = None
cla_isdr: int|None = None
is_sgp22 = False
is_sgp32 = False
profile_switch_requested: bytes|None = None
network_reject_scheduled: bool = False

pin_names = {0x01: 'PIN1', 0x02: 'PIN2', 0x03: 'PIN3', 0x04: 'PIN4',
             0x05: 'PIN5', 0x06: 'PIN6', 0x07: 'PIN7', 0x08: 'PIN8',
             0x0A: 'ADM1', 0x0B: 'ADM2', 0x0C: 'ADM3', 0x0D: 'ADM4',
             0x0E: 'ADM5', 0x11: 'UNIV', 0x81: '2PIN1', 0x82: '2PIN2',
             0x83: '2PIN3', 0x84: '2PIN4', 0x85: '2PIN5', 0x86: '2PIN6',
             0x87: '2PIN7', 0x88: '2PIN8', 0x8A: 'ADM6', 0x8B: 'ADM7',
             0x8C: 'ADM8', 0x8D: 'ADM9', 0x8E: 'ADM10'}

async def main():
    global negotiated_poll_interval, is_thales, cla_ipae, cla_isdr, has_5g, is_sgp22, is_sgp32, profile_switch_requested, network_type, network_reject_scheduled

    asyncio.get_running_loop().set_exception_handler(exc_handler)

    cli_process_task = None
    cli_input_task = None
    currently_active_profile = None
    profile_changed = False

    while True:
        card_reset_event.clear()
        sc.reset()

        try:
            send_terminal_capability()
            cla_isdr = open_logical_channel()
            cla_ipae = open_logical_channel()
            is_sgp22, is_sgp32 = select_isd_r(cla_isdr)
            if profile_switch_requested:
                logger.info('Profile switch requested, switching to %s', parse_iccid(profile_switch_requested))
                result = switch_profile(cla_isdr, profile_switch_requested)
                profile_switch_requested = False
                if result:
                    logger.info('Resetting the card after successful profile switch')
                    continue  # reset the card
            get_euicc_info(cla_isdr)
            try:
                get_profiles(cla_isdr)
            except BaseException as e:
                logger.error('Exception when listing profiles', exc_info=e)
            newly_active_profile = None
            for profile in profiles:
                if profile.enabled:
                    newly_active_profile = profile.iccid
                    break
            if newly_active_profile is not None and currently_active_profile is not None and currently_active_profile != newly_active_profile:
                profile_changed = True
            currently_active_profile = newly_active_profile
            if is_sgp32:
                enable_ipae(cla_isdr)
                try:
                    select_ipae(cla_ipae)  # Thales only
                    logger.info('Thales SIM detected')
                    is_thales = True
                except APDUException as e:
                    logger.warning('Not a Thales SIM')
                try:
                    get_ipae_version(cla_ipae)
                except APDUException as e:
                    logger.warning('IPAe busy')

        except APDUException:
            logger.error('SIM does not appear to be a SGP.22/SGP.32 eUICC')


        usim_aid = get_usim_aid()
        if not usim_aid:
            logger.error('Cannot find USIM AID')
            await asyncio.sleep(5)
            break

        fcp = parse_tags(select_usim(usim_aid))

        pin_status_template = parse_tags(fcp[b'\x62'][0][b'\xc6'][0])
        ps_num_bytes = len(pin_status_template[b'\x90'][0])
        pin_statuses = int.from_bytes(pin_status_template[b'\x90'][0], byteorder='big')
        needs_verification = False
        for i, pin in enumerate(pin_status_template.get(b'\x83', []), start=1):
            enabled = (pin_statuses & (1 << (ps_num_bytes * 8 - i))) != 0
            logger.info('%s enabled: %s', pin_names[pin[0]], enabled)
            if pin[0] == 0x01 and enabled:
                needs_verification = True

        if needs_verification:
            remaining_tries = get_pin_attempts(0x01)

            logger.info('PIN tries remaining: %d', remaining_tries)
            if remaining_tries == 0:
                logger.error('PIN is blocked, aborting')
                await asyncio.sleep(5)
                break
            elif remaining_tries == 1:
                logger.warning('Only 1 PIN try remaining, refusing to proceed')
                await asyncio.sleep(5)
                break

            if args.pin is None:
                logger.error('PIN is required')
                await asyncio.sleep(5)
                break

            try:
                # verify the PIN
                sc.transmit(cla=0x00, ins=0x20, p1=0x00, p2=0x01, data=args.pin.encode('ascii').ljust(8, b'\xFF'))
            except APDUException as e:
                if e.sw1 == 0x63 and e.sw2 & 0xF0 == 0xC0:
                    remaining_tries = e.sw2 & 0x0F
                    logger.error('PIN verification failed! %d remaining attempts', remaining_tries)
                    await asyncio.sleep(5)
                    break
                else:
                    raise e from None
        try:
            # Check if 5G is available on the SIM
            sc.transmit(cla=0x00, ins=0xA4, p1=0x00, p2=0x0C, data=b'\x5F\xC0')
            sc.transmit(cla=0x00, ins=0xA4, p1=0x00, p2=0x0C, data=b'\x7F\xFF')
        except APDUException:
            logger.warning('5G not available on the SIM')
        else:
            logger.info('5G is available')
            has_5g = True

        try:
            if network_reject_scheduled and profile_changed:
                network_type = NetworkType.disconnected
                update_location_no_service()
            else:
                match network_type:
                    case NetworkType.eutran:
                        update_location_eutran(location)
                    case NetworkType.disconnected:
                        update_location_no_service()
                    case _:
                        logger.error('Unhandled network type')
        except BaseException as e:
            logger.error('Error updating location information, 4G not available?', exc_info=e)

        send_terminal_profile()
        # initial setup:
        try:
            while sc.refresh_needed is not None:
                process_proactive_command(fetch())
        except Exception as e:
            logger.error('Error', exc_info=e)
            await asyncio.sleep(5)
            break
        logger.info('Initial setup done')
        if negotiated_poll_interval is None:
            logger.warning('Card did not set up a poll interval! Using 30s as default')
            negotiated_poll_interval = 30

        if network_reject_scheduled and profile_changed:
            network_reject_scheduled = False
            if Event.NETWORK_REJECTION not in requested_event_list:
                logger.error('NETWORK REJECTION not in event list')
            else:
                logger.info('Sending a network rejection event')
                data = bytearray()
                data += EventList([Event.NETWORK_REJECTION], cr=False)
                data += DeviceIdentities(source=DeviceIdentity.NETWORK, destination=DeviceIdentity.UICC, cr=False)
                data += TrackingAreaIdentification(location.tai, cr=False)
                data += AccessTechnology([ACT.EUTRAN], cr=False)
                data += UpdateAttachRegistrationType(type=RegistrationType.EPS_ATTACH, cr=False)
                data += RejectionCauseCode(code=RegistrationRejectionCode.PLMN_NOT_ALLOWED, cr=False)
                await send_event(data)

        polling_task = asyncio.create_task(poll())
        refresh_task = asyncio.create_task(do_refresh())
        if cli_process_task is None:
            cli_process_task = asyncio.create_task(cli())
        if cli_input_task is None:
            cli_input_task = asyncio.create_task(asyncio.to_thread(cli_input_thread, asyncio.get_running_loop()))
        card_reset_task = asyncio.create_task(card_reset_event.wait())

        done, pending = await asyncio.wait((polling_task, refresh_task, cli_input_task, cli_process_task, card_reset_task), return_when=asyncio.FIRST_COMPLETED)
        if len(done) == 1 and card_reset_task in done:
            # card reset was requested
            polling_task.cancel()
            refresh_task.cancel()
            close_all_tasks()
            continue
        else:
            for task in pending:
                task.cancel()
            break


def exc_handler(loop, context):
    if (exc := context.get('exception')) is not None:
        kw = {'exc_info': exc}
    else:
        kw = {}
    from pathlib import Path
    if exc is not None:
        Path('error.log').write_text('\n'.join(traceback.format_exception(exc)))
    logger.error('Exception: %s', context['message'], **kw)


main_window: curses.window|None = None
screen: curses.window|None = None
editscreen: curses.window|None = None
textinput: curses.textpad.Textbox|None = None
pad_scroll = 0

def run_main(stdscr: curses.window):
    global screen
    global textinput
    global editscreen
    global main_window

    main_window = stdscr
    stdscr.idlok(True)

    screen = curses.newpad(SCROLLBACK, curses.COLS)
    screen.clear()
    screen.idlok(True)
    screen.scrollok(True)
    screen.leaveok(True)

    stdscr.hline(curses.LINES - PROMPT_LINES - 1, 0, curses.ACS_HLINE, curses.COLS)
    border_window = stdscr.subwin(PROMPT_LINES, curses.COLS, curses.LINES - PROMPT_LINES, 0)
    border_window.border()
    editscreen = stdscr.subwin(PROMPT_LINES-2, curses.COLS-2, curses.LINES - PROMPT_LINES + 1, 1)
    editscreen.clear()
    editscreen.idlok(True)

    class Textbox(curses.textpad.Textbox):
        def do_command(self, ch: str | int) -> int:
            if ch == ord('\n'):
                return 0
            else:
                return super().do_command(ch)

    textinput = Textbox(editscreen, insert_mode=True)
    editscreen.move(0, 0)
    stdscr.noutrefresh()
    border_window.noutrefresh()
    flush_screen()

    class TerminalIO:
        def write(self, data: str) -> int:
            print_screen(data, end='', flush=False)
            return len(data)

        def flush(self):
            flush_screen()

    logging.basicConfig(stream=TerminalIO(), level=logging.DEBUG)

    asyncio.run(main(), debug=False)

try:
    curses.wrapper(run_main)
except Exception as e:
    traceback.print_exception(e)
finally:
    os._exit(0)
