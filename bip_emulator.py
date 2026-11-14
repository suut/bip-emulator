#!/usr/bin/env python3
# coding: utf-8

import logging
import shlex

logging.basicConfig(filename='bip_emulator.log', level=logging.DEBUG)
logger = logging.getLogger('bip-emulator')

from time import time
import socket

from enum import IntEnum

from tlv_utils import parse_tag, parse_tags, parse_length, parse_comprehension_tlv_tag, encode_tlv, CTLV
from smartcard_utils import APDUException, Smartcard, es10x

import asyncio
import sys
import threading
import argparse

refresh_event = asyncio.Event()
sc = Smartcard(refresh_event=refresh_event)
sc.connect()

USIM_AID = bytes.fromhex('A0000000871002')
EF_LOCI = bytes.fromhex('6F7E')
EF_PSLOCI = bytes.fromhex('6F73')
EF_EPSLOCI = bytes.fromhex('6FE3')

ID_TERMINAL = 0x82
ID_UICC = 0x81
ID_CHANNEL = 0x20

RES_SUCCESS = 0x00
RES_COMMAND_TYPE_NOT_UNDERSTOOD = 0x31
RES_COMMAND_DATA_NOT_UNDERSTOOD = 0x32
RES_ACTION_IN_CONTRADICTION_WITH_CURRENT_TIMER_STATE = 0x24
RES_COMMAND_CANNOT_BE_PROCESSED_CURRENTLY = 0x20

RES_EXTRA_NO_SERVICE = 0x04

class Event(IntEnum):
    LOCATION_STATUS = 0x03
    DATA_AVAILABLE = 0x09
    CHANNEL_STATUS = 0x0A

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
DeviceIdentity = CTLV.make_type('DeviceIdentity', 0x02, False, {'source': (0, 1, int), 'destination': (1, 1, int)})  # type: ignore
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

class Location:
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

parser = argparse.ArgumentParser(description='BIP modem emulator')
parser.add_argument('--mcc', default='204', help='Mobile country code (default %(default)s)')
parser.add_argument('--mnc', default='04', help='Mobile network code (default %(default)s)')
parser.add_argument('--imei', default='356358231187560', help='IMEI (default %(default)s)')
parser.add_argument('--network', choices=('none', '2G', '3G', '4G', '5G'), default='4G', help='Network type (default %(default)s; choices %(choices)s)')
args = parser.parse_args()

if args.network != '4G':
    raise NotImplementedError(f'Network {args.network} not implemented yet')

location = Location(args.mcc, args.mnc)
imei = args.imei
service = True


def select_usim():
    sc.transmit(cla=0x00, ins=0xA4, p1=0x04, p2=0x00, data=USIM_AID, le=0)


def update_location_info(loc: Location):
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
        self.task = asyncio.create_task(self.run_timer())

    @property
    def remaining_time(self):
        if self.expired:
            return 0

        if self.running:
            return max(0, self.timer_value - (time() - self.start_time))
        else:
            return self.timer_value

    async def run_timer(self):
        global timer_value
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
        data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC, cr=True)
        data += TimerIdentifier(identifier=self.timer_id, cr=True)
        data += TimerValue((0x00, 0x00, 0x00), cr=True)

        while True:
            try:
                sc.transmit(cla=0x80, ins=0xC2, p1=0x00, p2=0x00, data=encode_tlv(b'\xD7', data))
                break
            except APDUException as e:
                if e.sw1 == 0x93 and e.sw2 == 0x00:
                    await asyncio.sleep(5)
                else:
                    raise e
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
        self.task = asyncio.create_task(self.run_task())

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

    async def run_reader(self):
        while True:
            await self.read_event.wait()
            with self.read_lock:
                self.read_event.clear()
                datagram_length = len(self.datagrams[0])
            logger.info('Sending ENVELOPE (EVENT DOWNLOAD - Data available)')
            data = bytearray()
            data += EventList((Event.DATA_AVAILABLE,), cr=True)
            data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC, cr=True)
            data += ChannelStatus(status=self.channel_id | 0x80, extra=0x00, cr=True)  # TODO: check in the test spec
            data += ChannelDataLength(length=min(255, datagram_length), cr=True)
            sc.transmit(cla=0x80, ins=0xC2, p1=0x00, p2=0x00, data=encode_tlv(b'\xD6', data))

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
            data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC, cr=True)
            data += ChannelStatus(status=self.channel_id | 0x80, extra=0x00, cr=True)  # TODO: check in the test spec
            data += ChannelDataLength(length=min(255, len(self.recv_buffer)), cr=True)
            sc.transmit(cla=0x80, ins=0xC2, p1=0x00, p2=0x00, data=encode_tlv(b'\xD6', data))
            await asyncio.sleep(0)

        # TODO: wait for all the data to be read then send the event
        await asyncio.sleep(10)  # give an opportunity to process the proactive commands first

        # Send the channel closed event
        logger.info('Sending ENVELOPE (EVENT DOWNLOAD - Channel status)')
        data = bytearray()
        data += EventList((Event.CHANNEL_STATUS,), cr=True)
        data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC, cr=True)
        data += ChannelStatus(status=self.channel_id, extra=0x00, cr=True)  # TODO: check in the test spec
        sc.transmit(cla=0x80, ins=0xC2, p1=0x00, p2=0x00, data=encode_tlv(b'\xD6', data))


    async def run_task(self):
        reader, writer = await asyncio.open_connection(sock=self.socket)
        self.reader_task = asyncio.create_task(self.run_reader(reader))
        self.writer_task = asyncio.create_task(self.run_writer(writer))
        try:
            done, pending = await asyncio.wait((self.reader_task, self.writer_task), return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
        except asyncio.CancelledError:
            self.reader_task.cancel()
            self.writer_task.cancel()

    def connect(self):
        assert self.socket is not None and self.addr is not None
        self.socket.connect((self.addr, self.port))
        self.socket.settimeout(0.5)
        self.connected = True
        self.task = asyncio.create_task(self.run_task())



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
        if tag in tags:
            raise ValueError('Duplicate tag')
        tags[tag] = CTLV.parse(tag, cr, data)
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
                data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)  # device identities: terminal to UICC
                data += Result(result=RES_SUCCESS) # result: success
                data += Duration(unit=poll_interval_unit, interval=poll_interval_raw) # duration
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.SET_UP_EVENT_LIST:
                logger.info('processing SET UP EVENT LIST')
                requested_event_list = [*tags[EventList].data]
                data = bytearray()
                data += tags[CommandDetails]
                data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                data += Result(result=RES_SUCCESS)
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.PROVIDE_LOCAL_INFORMATION:
                logger.info('processing PROVIDE LOCAL INFORMATION')
                match tags[CommandDetails].command_data:
                    case 0x00:  # location information
                        # LTE
                        data = bytearray()
                        data += tags[CommandDetails]
                        data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                        if service:
                            data += Result(result=RES_SUCCESS)
                            data += LocalInformation(location.mcc_mnc + bytes.fromhex(location.tac) + location.eci)  # E-UTRAN
                        else:
                            data += Result(result=RES_COMMAND_CANNOT_BE_PROCESSED_CURRENTLY, extra=RES_EXTRA_NO_SERVICE)
                        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                    case 0x01:  # IMEI
                        data = bytearray()
                        data += tags[CommandDetails]
                        data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                        data += Result(result=RES_SUCCESS)
                        imei_array = bytearray.fromhex(('A' + imei).ljust(16, 'F'))
                        for i in range(len(imei_array)):
                            imei_array[i] = ((imei_array[i] & 0xF0) >> 4) | ((imei_array[i] & 0x0F) << 4)

                        data += Imei(imei_array)
                        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                    case info_type:
                        logger.warning(f'Unknown local information type {info_type:02X}')
                        data = bytearray()
                        data += tags[CommandDetails]
                        data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                        data += Result(result=RES_COMMAND_DATA_NOT_UNDERSTOOD)
                        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.TIMER_MANAGEMENT:
                logger.info('processing TIMER MANAGEMENT')
                timer_id = tags[TimerIdentifier].identifier
                match tags[CommandDetails].command_data:
                    case 0:  # start
                        value = decode_timer_value(tags[TimerValue].data)
                        timers[timer_id] = Timer(timer_id, value)
                        timers[timer_id].start_timer()
                        data = bytearray()
                        data += tags[CommandDetails]
                        data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                        data += Result(result=RES_SUCCESS)
                        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)

                    case 1:  # deactivate
                        if timers[timer_id].running:
                            timers[timer_id].stop_timer()
                            remaining_time = encode_timer_value(timers[timer_id].remaining_time)
                            data = bytearray()
                            data += tags[CommandDetails]
                            data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                            data += Result(result=RES_SUCCESS)
                            data += timer_value(remaining_time)
                            sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                        else:
                            data = bytearray()
                            data += tags[CommandDetails]
                            data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                            data += Result(result=RES_ACTION_IN_CONTRADICTION_WITH_CURRENT_TIMER_STATE)
                            sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                    case 2:  # get current value
                        if timers[timer_id].running:
                            remaining_time = encode_timer_value(timers[timer_id].remaining_time)
                            data = bytearray()
                            data += tags[CommandDetails]
                            data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                            data += Result(result=RES_SUCCESS)
                            data += timer_value(remaining_time)
                            sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                        else:
                            data = bytearray()
                            data += tags[CommandDetails]
                            data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                            data += Result(result=RES_SUCCESS)
                            sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
                    case cmd:
                        logger.warning(f'Unknown timer management command {cmd:02X}')
                        data = bytearray()
                        data += tags[CommandDetails]
                        data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                        data += Result(result=RES_COMMAND_DATA_NOT_UNDERSTOOD)
                        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.OPEN_CHANNEL:
                logger.info('processing OPEN CHANNEL')

                port = None
                proto = None
                req_buffer_size = 1400
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
                data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                data += Result(result=RES_SUCCESS)

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
                assert ID_CHANNEL + 1 <= tags[DeviceIdentity].destination <= ID_CHANNEL + 7
                channel_number = tags[DeviceIdentity].destination - ID_CHANNEL
                if channels[channel_number - 1] is not None:
                    channels[channel_number - 1].close()
                    channels[channel_number - 1] = None

                data = bytearray()
                data += tags[CommandDetails]
                data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                data += Result(result=RES_SUCCESS)
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.SEND_DATA:
                logger.info('Got SEND DATA command')
                assert ID_CHANNEL + 1 <= tags[DeviceIdentity].destination <= ID_CHANNEL + 7
                channel_id = tags[DeviceIdentity].destination - ID_CHANNEL
                channel = channels[channel_id - 1]
                if channel is None:
                    raise CommandDataNotUnderstood()
                logger.debug('calling write')
                channel.write(tags[ChannelData].data, tags[CommandDetails].command_data & 0x01)
                data = bytearray()
                data += tags[CommandDetails]
                data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                data += Result(result=RES_SUCCESS)
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.RECEIVE_DATA:
                logger.info('Got RECEIVE DATA command')
                assert ID_CHANNEL + 1 <= tags[DeviceIdentity].destination <= ID_CHANNEL + 7
                channel_id = tags[DeviceIdentity].destination - ID_CHANNEL
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
                data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
                data += Result(result=RES_SUCCESS)
                data += ChannelData(to_send)
                data += ChannelDataLength(bytes((min(255, remaining),)))
                sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
            case Command.REFRESH:
                logger.info('Processing command REFRESH')
                sys.exit(0)  # TODO
            case cmd:
                logger.warning(f'unknown proactive command {cmd:02X}')
                raise CommandTypeNotUnderstood()
    except CommandDataNotUnderstood:
        data = bytearray()
        data += tags[CommandDetails]
        data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
        data += Result(result=RES_COMMAND_DATA_NOT_UNDERSTOOD)
        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
    except CommandTypeNotUnderstood:
        data = bytearray()
        data += tags[CommandDetails]
        data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
        data += Result(result=RES_COMMAND_TYPE_NOT_UNDERSTOOD)
        sc.transmit(cla=0x80, ins=0x14, p1=0x00, p2=0x00, data=data)
    except CommandCannotBeProcessedCurrently:
        data = bytearray()
        data += tags[CommandDetails]
        data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC)
        data += Result(result=RES_COMMAND_CANNOT_BE_PROCESSED_CURRENTLY, extra=0x00)  # no specific cause can be given
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


euicc_categories = ['other', 'basicEuicc', 'mediumEuicc', 'contactlessEuicc']
ipa_modes = ['IPAd', 'IPAe']

def get_euicc_info(cla, is_sgp32=False):
    """
    ISD-R must be selected
    """
    tags = parse_tags(es10x(sc, cla, bytes.fromhex('BF3E035C015A'), max_command_data=max_command_data))
    eid = tags[b'\xbf\x3e'][0][b'\x5a'][0].hex().upper()
    logger.info('EID: %s', eid)
    print('EID:', eid)

    tags = parse_tags(es10x(sc, cla, bytes.fromhex('BF2200'), max_command_data=max_command_data))[b'\xbf\x22'][0]
    profile_version = '.'.join(map(str, tags[b'\x81'][0]))
    sgp22_version = '.'.join(map(str, tags[b'\x82'][0]))
    fw_version = '.'.join(map(str, tags[b'\x83'][0]))
    ts102241_version = '.'.join(map(str, tags[b'\x86'][0])) if b'\x86' in tags else None
    category = euicc_categories[tags[b'\x8B'][0][0]] if b'\x8B' in tags else None
    pp_version = '.'.join(map(str, tags[b'\x04'][0]))
    sas_accreditation_number = tags[b'\x0C'][0].decode('utf-8')
    if is_sgp32:
        ipa_mode = ipa_modes[tags[b'\x90'][0][0]]
        sgp32_version = ', '.join('.'.join(map(str, ver)) for ver in tags[b'\xb4'][0][b'\xa0'][0][b'\x04'])
        ecall_supported = b'\x81' in tags[b'\xb4'][0]
        fallback_supported = b'\x82' in tags[b'\xb4'][0]
        fallback_allowed_update_supported = b'\x83' in tags[b'\xb4'][0]

    logger.info('SGP.22 version: %s', sgp22_version)
    print('SGP.22 version:', sgp22_version)
    logger.info('Base eUICC Profile package version: %s', profile_version)
    print('Base eUICC Profile package version:', profile_version)
    logger.info('eUICC firmware version: %s', fw_version)
    print('eUICC firmware version:', fw_version)
    logger.info('ETSI TS 102 241 (UICC API for JavaCard) version: %s', ts102241_version)
    print('ETSI TS 102 241 (UICC API for JavaCard) version:', ts102241_version)
    logger.info('eUICC category: %s', category)
    print('eUICC category:', category)
    logger.info('Profile protection version: %s', pp_version)
    print('Profile protection version:', pp_version)
    logger.info('SAS accreditation number: %s', sas_accreditation_number)
    print('SAS accreditation number:', sas_accreditation_number)
    if is_sgp32:
        print()
        # logger.info('IPA mode: %s', ipa_mode)
        # print('IPA mode:', ipa_mode)
        logger.info('SGP.32 version: %s', sgp32_version)
        print('SGP.32 version:', sgp32_version)
        logger.info('Emergency call supported: %s', ecall_supported)
        print('Emergency call supported:', ecall_supported)
        logger.info('Fallback mechanism supported: %s', fallback_supported)
        print('Fallback mechanism supported:', fallback_supported)
        logger.info('Support for update of the Fallback Allowed metadata via ES6: %s', fallback_allowed_update_supported)
        print('Support for update of the Fallback Allowed metadata via ES6:', fallback_allowed_update_supported)


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


def select_isd_r(cla) -> bool:
    global max_command_data
    ISD_R_AID = bytes.fromhex('A0000005591010FFFFFFFF8900000100')
    fci = parse_tags(sc.transmit(cla=cla, ins=0xA4, p1=0x04, p2=0x0C, data=ISD_R_AID))
    max_command_data = int.from_bytes(fci[b'\x6f'][0][b'\xa5'][0][b'\x9f\x65'][0], byteorder='big')
    sgp32 = b'\xE1' in fci[b'\x6F'][0]

    if not sgp32:
        logger.warning('No SGP.32 support')
        print('No SGP.32 support')
    else:
        logger.info('SGP.32 eUICC')
        print('SGP.32 eUICC')

        bitstring = fci[b'\x6F'][0][b'\xE1'][0][b'\x80'][0]
        unused_bits = bitstring[0]
        value = int.from_bytes(bitstring[1:], byteorder='big') >> unused_bits
        value = f'{value:b}'.ljust(2, '0')
        ipae_supported = value[0] == '1'
        profile_enabled = value[1] == '1'
        logger.info('IPAe supported: %s', ipae_supported)
        logger.info('Profile enabled: %s', profile_enabled)

        print('IPAe supported:', ipae_supported)
        print('Profile enabled:', profile_enabled)

    return sgp32


def get_ipae_version(cla):
    ipae_version = sc.transmit(cla=cla|0x80, ins=0xCA, p1=0x00, p2=0x01, le=0x00)
    logger.info('IPAe version: %s', '.'.join(map(str, ipae_version)))
    print('IPAe version:', '.'.join(map(str, ipae_version)))


def select_ipae(cla):
    IPAE_AID = bytes.fromhex('A00000084455F1279166010101')
    sc.transmit(cla=cla, ins=0xA4, p1=0x04, p2=0x0C, data=IPAE_AID)


def send_terminal_capability():
    sc.transmit(cla=0x80, ins=0xAA, p1=0x00, p2=0x00, data=bytes.fromhex('A903840101'))


cli_line: str|None = None
cli_line_processed_event = threading.Event()
cli_line_available_event = asyncio.Event()
is_thales = False

def cli_input_thread(loop: asyncio.AbstractEventLoop):
    global cli_line
    while True:
        cli_line = input('$ ')
        loop.call_soon_threadsafe(cli_line_available_event.set)
        cli_line_processed_event.wait()
        cli_line_processed_event.clear()


async def cli():
    global service

    cli_parser = argparse.ArgumentParser(prog='', description='cli', exit_on_error=False, add_help=False)
    subparsers = cli_parser.add_subparsers(dest='command')
    help_parser = subparsers.add_parser('help')
    network_parser = subparsers.add_parser('network')
    poll_parser = subparsers.add_parser('poll', help='Force polling on a Thales eUICC')
    network_subparsers = network_parser.add_subparsers(dest='network_command')
    network_subparsers.add_parser('disconnect')
    network_subparsers.add_parser('connect')
    while True:
        await cli_line_available_event.wait()
        cli_line_available_event.clear()
        assert cli_line is not None
        try:
            args = cli_parser.parse_args(shlex.split(cli_line))
        except (argparse.ArgumentError, argparse.ArgumentTypeError) as e:
            print(e, file=sys.stderr)
        except SystemExit:
            pass  # help was printed
        else:
            match args.command:
                case 'help':
                    cli_parser.print_help()
                case 'network':
                    match args.network_command:
                        case 'disconnect':
                            if not service:
                                print('Already disconnected')
                            else:
                                print('Disconnecting from network')
                                await waiting_for_refresh.wait()
                                service = False
                                update_location_no_service()
                                if Event.LOCATION_STATUS in requested_event_list:
                                    logger.info('Sending ENVELOPE (EVENT DOWNLOAD - Location status)')
                                    data = bytearray()
                                    data += EventList((Event.LOCATION_STATUS,), cr=True)
                                    data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC, cr=True)
                                    data += LocationStatus(status=0x02, cr=True)  # No service
                                    sc.transmit(cla=0x80, ins=0xC2, p1=0x00, p2=0x00, data=encode_tlv(b'\xD6', data))
                                else:
                                    logger.warning('SIM did not set up Location status in the event list')
                        case 'connect':
                            if service:
                                print('Already connected')
                            else:
                                print('Connecting to network')
                                await waiting_for_refresh.wait()
                                service = True
                                update_location_info(location)
                                if Event.LOCATION_STATUS in requested_event_list:
                                    logger.info('Sending ENVELOPE (EVENT DOWNLOAD - Location status)')
                                    data = bytearray()
                                    data += EventList((Event.LOCATION_STATUS,), cr=True)
                                    data += DeviceIdentity(source=ID_TERMINAL, destination=ID_UICC, cr=True)
                                    data += LocationStatus(status=0x00, cr=True)  # Service available
                                    data += LocalInformation(location.mcc_mnc + bytes.fromhex(location.tac) + location.eci, cr=True)  # E-UTRAN
                                    sc.transmit(cla=0x80, ins=0xC2, p1=0x00, p2=0x00, data=encode_tlv(b'\xD6', data))
                                else:
                                    logger.warning('SIM did not set up Location status in the event list')
                case 'poll':
                    if not is_thales:
                        print('Not a Thales eUICC')
                    else:
                        if force_polling(cla_ipae):
                            print('Force polling success')
                        else:
                            print('Force polling failed; APDU polling is disabled or the IPAe is busy')

        cli_line_processed_event.set()

cla_ipae: int|None = None

async def main():
    global negotiated_poll_interval, is_thales, cla_ipae

    asyncio.get_running_loop().set_exception_handler(exc_handler)

    try:
        send_terminal_capability()
        cla_isdr = open_logical_channel()
        cla_ipae = open_logical_channel()
        is_sgp32 = select_isd_r(cla_isdr)
        get_euicc_info(cla_isdr, is_sgp32=is_sgp32)
        enable_ipae(cla_isdr)
        try:
            select_ipae(cla_ipae)  # Thales only
            logger.info('Thales SIM detected')
            print('Thales SIM detected')
            is_thales = True
            get_ipae_version(cla_ipae)
        except APDUException:
            logger.warning('Not a Thales SIM')

    except APDUException:
        logger.error('SIM does not appear to be a SGP.32 eUICC')
        print('SIM does not appear to be a eUICC')

    select_usim()
    update_location_info(location)
    send_terminal_profile()

    # initial setup:
    while sc.refresh_needed is not None:
        process_proactive_command(fetch())

    logger.info('Initial setup done')
    if negotiated_poll_interval is None:
        logger.warning('Card did not set up a poll interval! Using 30s as default')
        negotiated_poll_interval = 30

    polling_task = poll()
    refresh_task = do_refresh()
    cli_input_task = asyncio.create_task(asyncio.to_thread(cli_input_thread, asyncio.get_running_loop()))
    cli_process_task = cli()
    # force_polling_task = force_polling(cla_ipae)  # Thales only

    await asyncio.gather(polling_task, refresh_task, cli_input_task, cli_process_task)#, force_polling_task)


def exc_handler(loop, context):
    if context.get('exception') is not None:
        kw = {'exc_info': context['exception']}
    else:
        kw = {}
    logger.error('Exception: %s', context['message'], **kw)
    loop.default_exception_handler(context)

#
# def run_main(stdscr: curses.window):
#     stdscr.clear()
#     stdscr.idlok(True)
#     stdscr.scrollok(True)
#
#     class TerminalIO(io.RawIOBase):
#         def write(self, b):
#             stdscr.addstr(bytes(b).decode('utf-8'))
#             stdscr.refresh()
#             return len(b)
#
#         def writable(self) -> bool:
#             return True
#
#         def writelines(self, lines) -> None:
#             self.write(b''.join(lines))
#
#         def seekable(self) -> bool:
#             return False
#
#         def readable(self) -> bool:
#             return False
#
#         def isatty(self) -> bool:
#             return True
#
#         def flush(self):
#             stdscr.refresh()
#
#         def fileno(self) -> int:
#             return 1
#
#     tio = TerminalIO()
#     writer = io.BufferedWriter(tio)
#     wrapper = io.TextIOWrapper(writer, encoding='utf-8', newline='\n', line_buffering=True, write_through=True)
#     sys.stdout = sys.stderr = wrapper

asyncio.run(main(), debug=True)

# curses.wrapper(run_main)