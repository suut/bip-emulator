#!/usr/bin/env python3
# coding: utf-8


import smartcard


class APDUException(Exception):
    def __init__(self, ret, sw1, sw2):
        super().__init__(f'{sw1:02X} {sw2:02X}' if not ret else f'{ret.hex()}: {sw1:02X} {sw2:02X}')
        self.sw1 = sw1
        self.sw2 = sw2
        self.ret = ret


def make_apdu(cla, ins, p1, p2, data=b'', le=None) -> bytes:
    apdu = bytearray((cla, ins, p1, p2))
    if data:
        apdu += bytes((len(data),)) + data
    if le is not None:
        apdu += bytes((le,))
    return bytes(apdu)


class Smartcard:
    def __init__(self, refresh_event=None, reader=0):
        readers = smartcard.System.readers()
        self.reader = readers[reader]
        self.conn = self.reader.createConnection()
        self.refresh_needed: None|int = None
        self.refresh_event = refresh_event

    def connect(self):
        self.conn.connect()
        self.reset()

    def reset(self):
        self.conn.reconnect(protocol=smartcard.scard.SCARD_PROTOCOL_T0, disposition=smartcard.scard.SCARD_RESET_CARD)

    def transmit(self, cla, ins, p1, p2, data=b'', le=None) -> bytes:
        total_ret = bytearray()
        ret, sw1, sw2 = self.conn.transmit(list(make_apdu(cla, ins, p1, p2, data=data, le=le)))
        if sw1 == 0x6C:
            # need to re-send the command with a specific amount of data
            ret, sw1, sw2 = self.conn.transmit(list(make_apdu(cla, ins, p1, p2, data=data, le=sw2)))
        total_ret += bytes(ret)
        while sw1 == 0x61:
            ret, sw1, sw2 = self.conn.transmit(list(make_apdu(cla, 0xC0, 0x00, 0x00, le=sw2)))
            total_ret += bytes(ret)
        if not (sw1 == 0x90 and sw2 == 0x00):
            if sw1 == 0x91:
                # print('refresh needed')
                self.refresh_needed = sw2
                if self.refresh_event is not None:
                    self.refresh_event.set()
            else:
                raise APDUException(bytes(total_ret), sw1, sw2)
        else:
            self.refresh_needed = None
            if self.refresh_event is not None:
                self.refresh_event.clear()
        return bytes(total_ret)


def es10x(sc, cla, data, max_command_data=255):
    # STORE DATA
    max_blocks = (len(data) + max_command_data - 1) // max_command_data
    out = b''
    for i in range(max_blocks):
        more_blocks = 0x80 if i == max_blocks - 1 else 0x00
        out = sc.transmit(cla=cla|0x80, ins=0xE2, p1=0x11|more_blocks, p2=i, data=data[max_command_data*i:max_command_data*(i+1)], le=0)
    return out
