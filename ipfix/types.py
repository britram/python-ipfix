#
# ipfix/types.py
# (c) 2013 Brian Trammell <brian@trammell.ch>
# 
# (Licensing information here)
#

from datetime import datetime, timedelta
from functools import total_ordering
from ipaddress import ip_address
import struct

# constants
Varlen = 65535

# Exception
class IpfixTypeException(Exception):
    def __init__(self, *args):
        super().__init__(args)

# Table for downconverting struct elements for reduced length encoding
_stel_rle = { ('H', 1) : 'B',
              ('L', 2) : 'H',
              ('L', 1) : 'B',
              ('Q', 4) : 'L',
              ('Q', 2) : 'H',
              ('Q', 1) : 'B',
              ('h', 1) : 'b',
              ('l', 2) : 'h',
              ('l', 1) : 'b',
              ('q', 4) : 'l',
              ('q', 2) : 'h',
              ('q', 1) : 'b',
              ('d', 4) : 'f'}

# Builtin structs for varlen information
_varlen1_st = struct.Struct("!B")
_varlen2_st = struct.Struct("!H")

# Builtin type implementation

@total_ordering
class IpfixType:
    """
    Implements abstract interface for all IPFIX types.
    """
    def __init__(self, name, num, valenc, valdec):
        self.name = name
        self.num = num
        self.valenc = valenc
        self.valdec = valdec
        self.length = 0

    def __eq__(self, other):
        return (self.num, self.length) == (other.num, other.length)
    
    def __lt__(self, other):
        return (self.num, self.length) < (other.num, other.length)
    
    def __str__(self):
        return "<%s>" % self.name

    def __repr__(self):
        return "ipfix.types.for_name(%s)" % repr(self.name)

class StructType(IpfixType):
    def __init__(self, name, num, stel, valenc = _identity, valdec = _identity):
        super().__init__(name, num, valenc, valdec)
        self.stel = stel
        self.skipstel = str(self.length)+"x"
        self.st = struct.Struct("!"+stel)
        self.length = st.size

    def for_length(self, length):
        if not length or length == self.length:
            return self
        else:
            try:
                return StructType(self.name, self.num, _stel_rle[(self.stel, length)], self.valenc, self.valdec)
            except KeyError:
                raise IpfixTypeException("Reduced length encoding not supported <%s>[%u]" % (self.name, length))

    def encode_single_value_to(val, buf, offset, length):
        assert(self.length == length)
        self.st.pack_into(buf, offset, self.valenc(val))
    
    def decode_single_value_from(buf, offset, length):
        assert(self.length == length)
        return self.valdec(self.st.unpack_from(buf, offset))


class OctetArrayType(IpfixType):
    def __init__(self, name, num, valenc = lambda x: x, valdec = lambda x: x):
        super().__init__(name, num, valenc, valdec)
        self.length = Varlen
    
    def for_length(self):
        if not length or length == self.length:
            return self
        else:
            return StructType(self.name, self.num, str(length)+"s", self.valenc, self.valdec)

    def encode_single_value_to(val, buf, offset, length):
        buf[offset:offset+length] = self.valenc(val)

    def decode_single_value_from(buf, offset, length):
        return self.valdec(buf[offset:offset+length])

# Builtin encoders/decoders

def _identity(x):
    return x

def _encode_smibool(bool):
    if bool:
        return 1
    else:
        return 2

def _decode_smibool(byte):
    if byte == 1:
        return True
    else:
        return False

def _encode_utf8(string):   
    return string.encode()

def _decode_utf8(octets):
    return octets.decode()

def _encode_sec(dt):
    return dt.timestamp()
    
def _decode_sec(epoch):
    return datetime.utcfromtimestamp(epoch)
    
def _encode_msec(dt):
    return dt.timestamp() * 1000 + dt.microseconds / 1000
    
def _decode_msec(epoch):
    return datetime.utcfromtimestamp(epoch/1000) + timedelta(milliseconds = epoch % 1000)
    
def _encode_ntp(dt):
    raise NotImplementedError()

def _decode_ntp(ntp):
    raise NotImplementedError()

def _encode_ip(ipaddr):
    return ipaddr.packed()
    
def _decode_ip(octets):
    return ip_address(octets)
    
# Builtin type registry

# _Type_octetArray = OctetArrayType("octetArray", 0)
# _Type_unsigned8  = StructType("unsigned8",  1, "B")
# _Type_unsigned16 = StructType("unsigned16", 2, "H")
# _Type_unsigned32 = StructType("unsigned32", 3, "L")
# _Type_unsigned64 = StructType("unsigned64", 4, "Q")
# _Type_signed8    = StructType("signed8",    5, "b")
# _Type_signed16   = StructType("signed16",   6, "h")
# _Type_signed32   = StructType("signed32",   7, "l")
# _Type_signed64   = StructType("signed64",   8, "q")
# _Type_float32    = StructType("float32",    9, "f")
# _Type_float64    = StructType("float64",    10, "d")
# _Type_boolean    = StructType("boolean",    11, "B", _encode_smibool, _decode_smibool)
# _Type_macAddress = StructType("macAddress", 12, "6s")
# _Type_string     = OctetArrayType("string", 13, _encode_utf8, _decode_utf8)
# _Type_dateTimeSeconds =      StructType("dateTimeSeconds", 14, "L", _encode_sec, _decode_sec)
# _Type_dateTimeMilliseconds = StructType("dateTimeSeconds", 15, "Q", _encode_msec, _decode_msec)
# _Type_dateTimeMicroseconds = StructType("dateTimeMicroseconds", 16, "Q", _encode_ntp, _decode_ntp)
# _Type_dateTimeNanoseconds =  StructType("dateTimeNanoseconds", 17, "Q", _encode_ntp, _decode_ntp)
# _Type_ipv4Address = StructType("ipv4Address", 18, "4s", _encode_ip, _decode_ip)
# _Type_ipv6Address = IpAddressType("ipv6Address", 19, "16s", _encode_ip, _decode_ip)

# _TypeForName = {'octetArray':           _Type_octetArray,
#                 'string':               _Type_string,
#                 'unsigned8':            _Type_unsigned8,
#                 'unsigned16':           _Type_unsigned16,
#                 'unsigned32':           _Type_unsigned32,
#                 'unsigned64':           _Type_unsigned64,
#                 'signed8':              _Type_signed8,
#                 'signed16':             _Type_signed16,
#                 'signed32':             _Type_signed32,
#                 'signed64':             _Type_signed64,
#                 'float32':              _Type_float32,
#                 'float64':              _Type_float64,
#                 'boolean':              _Type_boolean,
#                 'ipv4Address':          _Type_ipv4Address,
#                 'ipv6Address':          _Type_ipv6Address,
#                 'macAddress':           _Type_macAddress,
#                 'dateTimeSeconds':      _Type_dateTimeSeconds,
#                 'dateTimeMilliseconds': _Type_dateTimeMilliseconds,
#                 'dateTimeMicroseconds': _Type_dateTimeMicroseconds,
#                 'dateTimeNanoseconds':  _Type_dateTimeNanoseconds}


_Types = [
    OctetArrayType("octetArray", 0)
    StructType("unsigned8",  1, "B"),
    StructType("unsigned16", 2, "H"),
    StructType("unsigned32", 3, "L"),
    StructType("unsigned64", 4, "Q"),
    StructType("signed8",    5, "b"),
    StructType("signed16",   6, "h"),
    StructType("signed32",   7, "l"),
    StructType("signed64",   8, "q"),
    StructType("float32",    9, "f"),
    StructType("float64",    10, "d"),
    StructType("boolean",    11, "B", _encode_smibool, _decode_smibool),
    StructType("macAddress", 12, "6s"),
    OctetArrayType("string", 13, _encode_utf8, _decode_utf8),
    StructType("dateTimeSeconds", 14, "L", _encode_sec, _decode_sec),
    StructType("dateTimeSeconds", 15, "Q", _encode_msec, _decode_msec),
    StructType("dateTimeMicroseconds", 16, "Q", _encode_ntp, _decode_ntp),
    StructType("dateTimeNanoseconds", 17, "Q", _encode_ntp, _decode_ntp),
    StructType("ipv4Address", 18, "4s", _encode_ip, _decode_ip),
    IpAddressType("ipv6Address", 19, "16s", _encode_ip, _decode_ip)
]

_TypeForName = { ietype.name: ietype for ietype in _Types }
_TypeForNum = { ietype.num: ietype for ietype in _Types }

def for_name(name):
    try: 
        return _TypeForName[name]
    except KeyError:
        return None

def decode_varlen(buf, offset):
    length = _varlen1_st.unpack_from(buf, offset)
    offset += _varlen1_st.size
    if length == 255:
        length = _varlen2_st.unpack_from(buf, offset)
        offset += _varlen2_st.size
    return (length, offset)
    
def encode_varlen(length, buf, offset):
    if length >= 255:
        _varlen1.pack_into(buf, offset, 255)
        offset += _varlen1_st.size
        _varlen2.pack_into(buf, offset, length)
        offset += _varlen2_st.size
    else:
        _varlen1.pack_into(buf, offset, length)
        offset += _varlen1_st.size
    return offset
    