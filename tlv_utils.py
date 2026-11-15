#!/usr/bin/env python3
# coding: utf-8

import sys
from typing import Self
import io


def parse_tag(x: bytes, i: int) -> tuple[int, bytes, int, bool, int]:
    # parse tag
    fulltag = bytearray()
    tag_class = x[i] >> 6
    constructed = (x[i] & 0x20) != 0
    tag_number = 0

    fulltag.append(x[i])
    if (x[i] & 0x1F) == 0x1F:
        i += 1
        while x[i] & 0x80:
            fulltag.append(x[i])
            tag_number = (tag_number << 7) | (x[i] & 0x7F)
            i += 1
        fulltag.append(x[i])
        tag_number = (tag_number << 7) | x[i]
        i += 1

    else:
        tag_number = x[i] & 0x1F
        i += 1

    return i, bytes(fulltag), tag_class, constructed, tag_number


def parse_comprehension_tlv_tag(x: bytes, i: int) -> tuple[int, bool, bytes]:
    if 0x01 <= x[i] <= 0x7E:
        return i+1, False, bytes((x[i],))
    elif 0x80 <= x[i] <= 0xFE:
        return i+1, True, bytes((x[i] & 0x7F,))
    elif x[i] == 0x7F:
        tag = x[i+1:i+3]
        if tag[0] & 0x80:
            return i+3, True, bytes((tag[0] & 0x7F, tag[1]))
        else:
            return i+3, False, tag
    else:
        raise ValueError(f'invalid first byte {x[i]}')


def parse_length(x: bytes, i: int) -> tuple[int, int | None]:
    if x[i] & 0x80:
        ll = x[i] & 0x7F
        i += 1
        if ll == 0:
            return i, None
        l = int.from_bytes(x[i:i + ll], byteorder='big')
        return i + ll, l
    else:
        l = x[i]
        return i + 1, l


def parse_tags(data, break_on_ff=False):
    max_length = len(data)
    i = 0
    out = {}
    while i < max_length:
        if data[i] == 0xFF and break_on_ff:
            return out

        i, tag, tag_class, constructed, tag_number = parse_tag(data, i)
        i, length = parse_length(data, i)
        contents = data[i:i+length]

        if constructed:
            out.setdefault(tag, []).append(parse_tags(contents))
        else:
            out.setdefault(tag, []).append(contents)

        i += length

    assert i == max_length
    return out


def dump_tags(data: dict|bytes|bytearray, indent=0, output=sys.stdout):
    if not isinstance(data, dict):
        data = parse_tags(data)
    for k, v in data.items():
        if not isinstance(v, list):
            v = [v]
        for x in v:
            if isinstance(x, dict):
                print(indent * '  ' + k.hex(), file=output)
                dump_tags(x, indent=indent+1, output=output)
            else:
                print(indent * '  ' + k.hex() + ' ' + x.hex(), file=output)


def format_tags(data: dict|bytes|bytearray, indent=0) -> str:
    output = io.StringIO()
    dump_tags(data, indent=indent, output=output)
    contents = output.getvalue()
    output.close()
    return contents


def encode_tlv(t, v):
    if not isinstance(v, bytes):
        v = bytes(v)
    data = bytearray()
    data += t
    if len(v) < 128:
        data += len(v).to_bytes(length=1)
    elif len(v) < 256:
        data += b'\x81' + len(v).to_bytes(length=1)
    elif len(v) < 65536:
        data += b'\x82' + len(v).to_bytes(length=2, byteorder='big')
    else:
        raise ValueError('payload too big')
    data += v
    return bytes(data)


class CTLVElement:
    def __init__(self, tag, cr_default):
        if isinstance(tag, bytes):
            tag = bytearray(tag)
        else:
            tag = bytearray((tag,))
        self.cr_default = cr_default
        self.tag = bytes(tag)
        tag[0] |= 0x80
        self.tag_cr = bytes(tag)

    def __call__(self, *data, cr=None):
        if cr is None:
            cr = self.cr_default
        if len(data) == 1 and isinstance(data[0], (list, tuple, bytes, bytearray)):
            data = data[0]
        return encode_tlv(self.tag_cr if cr else self.tag, data)

    def __repr__(self):
        return f'{self.tag.hex().upper()}: {type(self).__name__} (Min={"Y" if self.cr_default else "N"})'


def make_getter(offset, size, attr_type):
    def field_getter(self: CTLV):
        if size is ...:
            assert offset <= len(self.data)
            attr = self.data[offset:]
        else:
            assert offset + size <= len(self.data)
            attr = self.data[offset:offset + size]
        if attr_type is int:
            return int.from_bytes(attr, byteorder='big')
        elif attr_type is bytes:
            return attr
        else:
            return attr_type(attr)
    return field_getter


def make_setter(offset, size, attr_type):
    def field_setter(self: CTLV, item):
        if attr_type is int:
            encoded_item = item.to_bytes(length=size if size is not ... else 1, byteorder='big')
        elif attr_type is bytes:
            encoded_item = item
        else:
            encoded_item = bytes(item)

        if size is ...:
            self.data = self.data[:offset] + encoded_item
        else:
            assert offset + size <= len(self.data)
            data = bytearray(self.data)
            data[offset:offset+size] = encoded_item
            self.data = bytes(data)
    return field_setter


class CTLV:
    TAG: bytes
    TAG_CR: bytes
    MIN: bool
    _FIELDS: dict[str, tuple[int, int|Ellipsis, type]]|None

    _REGISTERED_TAGS: dict[bytes, type[CTLV]] = {}

    def __new__(cls, *args, **kwargs) -> Self:
        assert all(hasattr(cls, x) for x in ('TAG', 'TAG_CR', 'MIN'))
        return super().__new__(cls)

    @classmethod
    def parse(cls, tag: bytes, cr: bool, data: bytes) -> CTLV:
        if tag in cls._REGISTERED_TAGS:
            return cls._REGISTERED_TAGS[tag](data, cr)
        else:
            return cls.make_type(f'Unknown-{tag.hex().upper()}', tag, False, register=False)(data, cr)

    @classmethod
    def make_type(cls, name: str, tag: int|bytes, min: bool, fields: dict[str, tuple[int, int|Ellipsis, type]]|None = None, register=True) -> type[CTLV]:
        if isinstance(tag, bytes):
            tag = bytearray(tag)
        else:
            tag = bytearray((tag,))
        tag_no_cr = bytes(tag)
        tag[0] |= 0x80
        tag_cr = bytes(tag)
        class_dict: dict = {'TAG': tag_no_cr, 'TAG_CR': tag_cr, 'MIN': min}
        if fields is not None:
            class_dict['_FIELDS'] = fields
            for field_name, (offset, size, attr_type) in fields.items():
                class_dict[field_name] = property(fget=make_getter(offset, size, attr_type), fset=make_setter(offset, size, attr_type))
        else:
            class_dict['_FIELDS'] = None
        klass = type(name, (cls,), class_dict)
        if register:
            cls._REGISTERED_TAGS[tag_no_cr] = klass
        return klass

    def __init__(self, data: bytes|list[int]|tuple[int]|None = None, cr: bool|None = None, **kwargs):
        if data is None:
            assert type(self)._FIELDS
            max_size: int = max(offset + size for offset, size, attr_type in type(self)._FIELDS.values() if size is not ...)
            self.data = bytes(max_size)
            for k, v in kwargs.items():
                setattr(self, k, v)
        else:
            self.data = bytes(data)
        self.cr = cr if cr is not None else type(self).MIN

    def __bytes__(self):
        return encode_tlv(type(self).TAG if not self.cr else type(self).TAG_CR, self.data)

    def __add__(self, other):
        return bytes(self) + other

    def __radd__(self, other):
        return other + bytes(self)

    def __repr__(self) -> str:
        return f'{type(self).__name__}(CR={self.cr}): {self.data.hex()}'
