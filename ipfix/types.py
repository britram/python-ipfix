#
# ipfix/types.py
# (c) 2013 Brian Trammell <brian@trammell.ch>
# 
# (Licensing information here)
#

from datetime import datetime, timedelta
from ipaddress import ip_address
from struct import Struct

# constants
Varlen = 65535

# Builtin type implementation
class IpfixType:
    """
    Implements abstract interface for all IPFIX types.
    """
    def __init__(self, name, num):
        self.name = name
        self.num = num
    
    def __str__(self):
        return "<%s>" % self.name
        
    def __repr__(self):
        return "ipfix.types.for_name(%s)" % repr(self.name)
        
    def length(self):
        return 0;
    
    def decode_value_from(self, buf, offset, length):
        raise NotImplementedException()
    
    def encode_value_to(self, val, buf, offset, length):
        raise NotImplementedException()    


class BytesType(IpfixType):
    """An IPFIX byte array, without endian conversion"""
    def __init__(self, name, num, length):
        super().__init__(name, num)
        self.blength = length;
        
    def length(self):
        return self.blength;
    
    def decode_value_from(self, buf, offset, length):
        return bytes(buf[offset:offset+length])
    
    def encode_value_to(self, val, buf, offset, length):
        buf[offset:offset+length] = val


class IpAddressType(BytesType):
    """An IPv4 or IPv6 address, converted to python 3.x ip_address type"""
    def __init__(self, name, num, length):
        super().__init__(name, num, length)
    
    def decode_value_from(self, buf, offset, length):
        if length != self.length():
            raise ValueError("no RLE for addresses")
        return ip_address(bytes(buf[offset:offset+length]))
    
    def encode_value_to(self, val, buf, offset, length):
        if length != self.length():
            raise ValueError("no RLE for addresses")
        rsuper.encode_value_to(val.packed(), buf, offset, length)


class PackedType(IpfixType):
    """A scalar type packed using Python's struct facility"""
    def __init__(self, name, num, packstr, *rletypes):
        super().__init__(name, num)
        self.st = Struct(packstr)
        self.rletypes = rletypes
    
    def length(self):
        return self.st.size
    
    def decode_value_from(self, buf, offset, length):
        if length == self.length():
            return self.st.unpack_from(buf, offset)[0]
        else:
            for rletype in self.rletypes:
                if length == rletype.length():
                    return rletype.decode_value_from(buf, offset, length)
            raise ValueError("no RLE for type " + self.name + " length " + str(length))
    
    def encode_value_to(self, val, buf, offset, length):
        if length == self.length():
            return self.st.pack_into(buf, offset, val)
        else:
            for rletype in self.rletypes:
                if length == rletype.length():
                    return rletype.encode_value_to(val, buf, offset, length)
            raise ValueError("no RLE for type " + self.name + " length " + str(length))

class BooleanType(PackedType):
    """Encodes booleans using SMI conventions"""
    def __init__(self, name, num):
        super().__init__(name, num, "!B")
    
    def decode_value_from(self, buf, offset, length):
        return super().decode_value_from(buf, offset, length) == 1
    
    def encode_value_to(self, val, buf, offset, length):
        if val:
            smibool = 1
        else:
            smibool = 2
        super().encode_value_to(smibool, buf, offset, length)

class EpochSecondsType(PackedType):
    """Encodes python datetimes as unsigned32"""
    def __init__(self, name, num):
        super().__init__(name, num, "!L")
    
    def decode_value_from(self, buf, offset, length):
        return datetime.utcfromtimestamp(super().decode_value_from(buf, offset, length))
    
    def encode_value_to(self, val, buf, offset, length):
        super().encode_value_to(val.timestamp(), buf, offset, length)


class EpochMillisecondsType(PackedType):
    """Encodes python datetimes with millisecond precision as unsigned64"""
    def __init__(self, name, num):
        super().__init__(name, num, "!Q")
    
    def decode_value_from(self, buf, offset, length):
        val = super().decode_value_from(buf, offset, length)
        return datetime.utcfromtimestamp(val/1000) + timedelta(milliseconds = val % 1000)
    
    def encode_value_to(self, val, buf, offset, length):
         super().encode_value_to(val.timestamp() * 1000 + val.microseconds / 1000, 
                 buf, offset, length)

# Builtin type registry

_Type_octetArray = BytesType("octetArray",  0, Varlen)
_Type_unsigned8  = PackedType("unsigned8",  0, "!B")
_Type_unsigned16 = PackedType("unsigned16", 0, "!H", _Type_unsigned8)
_Type_unsigned32 = PackedType("unsigned32", 0, "!L", _Type_unsigned16, _Type_unsigned8)
_Type_unsigned64 = PackedType("unsigned64", 0, "!Q", _Type_unsigned32, _Type_unsigned16, _Type_unsigned8)
_Type_signed8    = PackedType("signed8",    0, "!b")
_Type_signed16   = PackedType("signed16",   0, "!h", _Type_signed8)
_Type_signed32   = PackedType("signed32",   0, "!l", _Type_signed16, _Type_signed8)
_Type_signed64   = PackedType("signed64",   0, "!q", _Type_signed32, _Type_signed16, _Type_signed8)
_Type_float32    = PackedType("float32",    0, "!f")
_Type_float64    = PackedType("float64",    0, "!d", _Type_float32)
_Type_boolean    = BooleanType("boolean",   0)
_Type_dateTimeSeconds = EpochSecondsType("dateTimeSeconds", 0)
_Type_dateTimeMilliseconds = EpochMillisecondsType("dateTimeMilliseconds", 0)
_Type_dateTimeMicroseconds = IpfixType("dateTimeMicroseconds", 0)
_Type_dateTimeNanoseconds =  IpfixType("dateTimeNanoseconds", 0)
_Type_ipv4Address = IpAddressType("ipv4Address", 0, 4)
_Type_ipv6Address = IpAddressType("ipv6Address", 0, 16)
_Type_macAddress = BytesType("macAddress", 0, 6)
_Type_string     = IpfixType("string", 0)

_TypeForName = {'octetArray':           _Type_octetArray,
                'string':               _Type_string,
                'unsigned8':            _Type_unsigned8,
                'unsigned16':           _Type_unsigned16,
                'unsigned32':           _Type_unsigned32,
                'unsigned64':           _Type_unsigned64,
                'signed8':              _Type_signed8,
                'signed16':             _Type_signed16,
                'signed32':             _Type_signed32,
                'signed64':             _Type_signed64,
                'float32':              _Type_float32,
                'float64':              _Type_float64,
                'boolean':              _Type_boolean,
                'ipv4Address':          _Type_ipv4Address,
                'ipv6Address':          _Type_ipv6Address,
                'macAddress':           _Type_macAddress,
                'dateTimeSeconds':      _Type_dateTimeSeconds,
                'dateTimeMilliseconds': _Type_dateTimeMilliseconds,
                'dateTimeMicroseconds': _Type_dateTimeMicroseconds,
                'dateTimeNanoseconds':  _Type_dateTimeNanoseconds}

def for_name(name):
    try: 
        return _TypeForName[name]
    except KeyError:
        return None
