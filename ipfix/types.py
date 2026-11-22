#
# python-ipfix (c) 2013-2026 Brian Trammell.
#
# Many thanks to the mPlane consortium (http://www.ict-mplane.eu) for
# its material support of this effort.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Implementation of IPFIX abstract data types (ADT) and mappings to Python types.

Maps each IPFIX ADT to the corresponding Python type, as below:

======================= =============
       IPFIX Type        Python Type
======================= =============
octetArray              bytes
unsigned8               int
unsigned16              int
unsigned32              int
unsigned64              int
unsigned256             int
signed8                 int
signed16                int
signed32                int
signed64                int
float32                 float
float64                 float
boolean                 bool
macAddress              bytes
string                  str
dateTimeSeconds         datetime
dateTimeMilliseconds    datetime
dateTimeMicroseconds    datetime
dateTimeNanoseconds     datetime
ipv4Address             ipaddress
ipv6Address             ipaddress
======================= =============

Though client code generally will not use this module directly, it defines how
each IPFIX abstract data type will be represented in Python, and the concrete
IPFIX representation of each type. Type methods operate on buffers, as used
internally by the :class:`ipfix.message.MessageBuffer` class, so we'll create
one to illustrate encoding and decoding:

>>> import ipfix.types
>>> buf = memoryview(bytearray(32))

Each of the encoding methods returns the offset into the buffer of the first
byte after the encoded value; since we're always encoding to the beginning
of the buffer in this example, this is equivalent to the length.
We use this to bound the encoded value on subsequent decode.

Integers are represented by the python int type:

>>> unsigned32 = ipfix.types.for_name("unsigned32")
>>> length = unsigned32.encode_single_value_to(42, buf, 0)
>>> buf[0:length].tolist()
[0, 0, 0, 42]
>>> unsigned32.decode_single_value_from(buf, 0, length)
42

...floats by the float type, with the usual caveats about precision:

>>> float32 = ipfix.types.for_name("float32")
>>> length = float32.encode_single_value_to(42.03579, buf, 0)
>>> buf[0:length].tolist()
[66, 40, 36, 166]
>>> float32.decode_single_value_from(buf, 0, length)
42.035789489746094

...strings by the str type, encoded as UTF-8:

>>> string = ipfix.types.for_name("string")
>>> length = string.encode_single_value_to("Grüezi", buf, 0)
>>> buf[0:length].tolist()
[71, 114, 195, 188, 101, 122, 105]
>>> print(string.decode_single_value_from(buf, 0, length))
Grüezi

...addresses as the IPv4Address and IPv6Address types in the ipaddress module:

>>> from ipaddress import ip_address
>>> ipv4Address = ipfix.types.for_name("ipv4Address")
>>> length = ipv4Address.encode_single_value_to(ip_address("198.51.100.27"), buf, 0)
>>> buf[0:length].tolist()
[198, 51, 100, 27]
>>> ipv4Address.decode_single_value_from(buf, 0, length)
IPv4Address('198.51.100.27')
>>> ipv6Address = ipfix.types.for_name("ipv6Address")
>>> length = ipv6Address.encode_single_value_to(ip_address("2001:db8::c0:ffee"), buf, 0)
>>> buf[0:length].tolist()
[32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 255, 238]
>>> ipv6Address.decode_single_value_from(buf, 0, length)
IPv6Address('2001:db8::c0:ffee')

...and the timestamps of various precision as a python datetime,
encoded as per RFC 7011:

>>> from datetime import datetime
>>> dtfmt = "%Y-%m-%d %H:%M:%S.%f"
>>> dt = datetime.strptime("2013-06-21 14:00:03.456789", dtfmt)

dateTimeSeconds truncates microseconds:

>>> dateTimeSeconds = ipfix.types.for_name("dateTimeSeconds")
>>> length = dateTimeSeconds.encode_single_value_to(dt, buf, 0)
>>> buf[0:length].tolist()
[81, 196, 92, 99]
>>> dateTimeSeconds.decode_single_value_from(buf, 0, length).strftime(dtfmt)
'2013-06-21 14:00:03.000000'

dateTimeMilliseconds truncates microseconds to the nearest millisecond:

>>> dateTimeMilliseconds = ipfix.types.for_name("dateTimeMilliseconds")
>>> length = dateTimeMilliseconds.encode_single_value_to(dt, buf, 0)
>>> buf[0:length].tolist()
[0, 0, 1, 63, 103, 8, 228, 128]
>>> dateTimeMilliseconds.decode_single_value_from(buf, 0, length).strftime(dtfmt)
'2013-06-21 14:00:03.456000'

dateTimeMicroseconds exports microseconds fully in NTP format:

>>> dateTimeMicroseconds = ipfix.types.for_name("dateTimeMicroseconds")
>>> length = dateTimeMicroseconds.encode_single_value_to(dt, buf, 0)
>>> buf[0:length].tolist()
[213, 110, 218, 227, 116, 240, 32, 0]
>>> dateTimeMicroseconds.decode_single_value_from(buf, 0, length).strftime(dtfmt)
'2013-06-21 14:00:03.456789'

dateTimeNanoseconds is also supported, but is identical to
dateTimeMicroseconds, as the datetime class in Python only supports
microsecond-level timing.

"""

import binascii
import math
import operator
import struct
from datetime import UTC, datetime
from functools import total_ordering
from ipaddress import ip_address

VARLEN = 65535

ISO8601_FMT = "%Y-%m-%d %H:%M:%S"

# Seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01)
NTP_EPOCH_TO_UNIX_EPOCH = 0x83AA7E80


class IpfixTypeError(ValueError):
    """Raised when attempting to do an unsupported operation on a type"""


_OCTET_ARRAY_NUM = 0
_FLOAT64_NUM = 10
_STRING_NUM = 13
_IPV4_NUM = 18

_SIGNED_INT_NUMS = frozenset({5, 6, 7, 8})
_INT_DEFAULT_LEN = {
    1: 1,
    2: 2,
    3: 4,
    4: 8,
    5: 1,
    6: 2,
    7: 4,
    8: 8,
    23: 32,
}
_INT_STRUCT_CODE = {
    (False, 1): "B",
    (False, 2): "H",
    (False, 4): "L",
    (False, 8): "Q",
    (True, 1): "b",
    (True, 2): "h",
    (True, 4): "l",
    (True, 8): "q",
}

# Builtin structs for varlen information
_varlen1_st = struct.Struct("!B")
_varlen2_st = struct.Struct("!H")


def _identity(x):
    return x


def _make_int_encoder(length, signed=False):
    def _encode_int_bytes(val):
        return operator.index(val).to_bytes(length, "big", signed=signed)

    return _encode_int_bytes


def _make_int_decoder(signed=False):
    def _decode_int_bytes(octets):
        return int.from_bytes(octets, "big", signed=signed)

    return _decode_int_bytes


def _make_fixed_utf8_encoder(length):
    def _encode_utf8_fixed(s):
        encoded = s.encode("utf-8")
        if len(encoded) > length:
            raise ValueError(
                f"UTF-8 encoded string ({len(encoded)} bytes) exceeds fixed length {length}"
            )
        return encoded

    return _encode_utf8_fixed


def _decode_utf8_fixed(octets):
    return octets.rstrip(b"\x00").decode("utf-8")


def _fixed_sequence_type(roottype, length):
    if roottype.num == _STRING_NUM:
        return StructType(
            roottype.name,
            roottype.num,
            f"{length}s",
            valenc=_make_fixed_utf8_encoder(length),
            valdec=_decode_utf8_fixed,
            valstr=roottype.valstr,
            valparse=roottype.valparse,
            roottype=roottype,
        )
    return StructType(
        roottype.name,
        roottype.num,
        f"{length}s",
        valenc=roottype.valenc,
        valdec=roottype.valdec,
        valstr=roottype.valstr,
        valparse=roottype.valparse,
        roottype=roottype,
    )


@total_ordering
class IpfixType:
    """Abstract interface for all IPFIX types. Used internally."""

    def __init__(self, name, num, valenc, valdec, valstr, valparse, roottype=None):
        self.name = name
        self.num = num
        self.valenc = valenc
        self.valdec = valdec
        self.valstr = valstr
        self.valparse = valparse
        self.roottype = roottype if roottype is not None else self
        self.length = 0

    def __eq__(self, other):
        if not isinstance(other, IpfixType):
            return NotImplemented
        return (self.num, self.length) == (other.num, other.length)

    def __lt__(self, other):
        if not isinstance(other, IpfixType):
            return NotImplemented
        return (self.num, self.length) < (other.num, other.length)

    def __str__(self):
        return f"<{self.name}>"

    def __repr__(self):
        return f"ipfix.types.for_name({self.name!r})"


class StructType(IpfixType):
    """Type encoded by struct packing. Used internally."""

    def __init__(
        self,
        name,
        num,
        stel,
        valenc=_identity,
        valdec=_identity,
        valstr=str,
        valparse=int,
        roottype=None,
    ):
        super().__init__(name, num, valenc, valdec, valstr, valparse, roottype=roottype)
        self.stel = stel
        self.st = struct.Struct("!" + stel)
        self.length = self.st.size
        self.skipel = f"{self.length}x"

    def for_length(self, length):
        if not length or length == self.length:
            return self
        if length < 0 or length > VARLEN:
            raise IpfixTypeError(f"Illegal length {length} for <{self.name}>")

        # OctetArray / string fixed-length or varlen re-sizing
        if self.num in (_OCTET_ARRAY_NUM, _STRING_NUM):
            if length == VARLEN:
                return self.roottype
            return _fixed_sequence_type(self.roottype, length)

        if length == VARLEN:
            raise IpfixTypeError(f"Illegal length {length} for <{self.name}>")

        # Reduced-size encoding for integer types (RFC 7011 §6.2, RFC 9740)
        default_len = _INT_DEFAULT_LEN.get(self.num)
        if default_len is not None and 1 <= length <= default_len:
            if length == default_len:
                return self.roottype
            signed = self.num in _SIGNED_INT_NUMS
            stel = _INT_STRUCT_CODE.get((signed, length))
            if stel is not None:
                return StructType(
                    self.name,
                    self.num,
                    stel,
                    valstr=self.roottype.valstr,
                    valparse=self.roottype.valparse,
                    roottype=self.roottype,
                )
            return StructType(
                self.name,
                self.num,
                f"{length}s",
                valenc=_make_int_encoder(length, signed=signed),
                valdec=_make_int_decoder(signed=signed),
                valstr=self.roottype.valstr,
                valparse=self.roottype.valparse,
                roottype=self.roottype,
            )

        # Reduced-size encoding for float64 -> float32 (RFC 7011 §6.2)
        if self.num == _FLOAT64_NUM:
            if length == 8:
                return self.roottype
            if length == 4:
                return StructType(
                    self.name,
                    self.num,
                    "f",
                    valstr=self.roottype.valstr,
                    valparse=self.roottype.valparse,
                    roottype=self.roottype,
                )

        raise IpfixTypeError(f"No RLE for <{self.name}>[{length}]")

    def encode_single_value_to(self, val, buf, offset):
        self.st.pack_into(buf, offset, self.valenc(val))
        return offset + self.length

    def decode_single_value_from(self, buf, offset, length):
        if self.length != length:
            raise IpfixTypeError(
                f"Length mismatch for <{self.name}>: expected {self.length}, got {length}"
            )
        return self.valdec(self.st.unpack_from(buf, offset)[0])


class OctetArrayType(IpfixType):
    """Type encoded by byte array packing. Used internally."""

    def __init__(
        self,
        name,
        num,
        valenc=_identity,
        valdec=_identity,
        valstr=binascii.hexlify,
        valparse=binascii.unhexlify,
        roottype=None,
    ):
        super().__init__(name, num, valenc, valdec, valstr, valparse, roottype=roottype)
        self.length = VARLEN

    def for_length(self, length):
        if not length or length == self.length:
            return self
        if length < 0 or length > VARLEN:
            raise IpfixTypeError(f"Illegal length {length} for <{self.name}>")
        return _fixed_sequence_type(self.roottype, length)

    def encode_single_value_to(self, val, buf, offset):
        enc = self.valenc(val)
        buf[offset : offset + len(enc)] = enc
        return offset + len(enc)

    def decode_single_value_from(self, buf, offset, length):
        return self.valdec(bytes(buf[offset : offset + length]))


# Utility calls for builtin encoders/decoders
def dt2epoch(dt):
    """Convert a datetime (aware or naive-as-UTC) to POSIX seconds since 1970-01-01T00:00:00Z."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


# Builtin encoders/decoders
def _encode_smibool(val):
    return 1 if val else 2


def _decode_smibool(byte):
    if byte == 1:
        return True
    if byte == 2:
        return False
    raise ValueError(f"invalid IPFIX boolean value {byte} (expected 1 or 2)")


def _str_bool(val):
    return "true" if val else "false"


def _parse_bool(string):
    return string == "true"


def _encode_utf8(string):
    return string.encode("utf-8")


def _decode_utf8(octets):
    return octets.decode("utf-8")


def _to_naive_utc(dt):
    if dt.tzinfo is not None:
        return dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def _parse_iso_dt(string):
    return _to_naive_utc(datetime.fromisoformat(string))


def _encode_sec(dt):
    return int(dt2epoch(dt))


def _decode_sec(epoch):
    return datetime.fromtimestamp(epoch, tz=UTC).replace(tzinfo=None)


def _str_sec(dt):
    return _to_naive_utc(dt).strftime(ISO8601_FMT)


def _encode_msec(dt):
    return int(dt2epoch(dt) * 1000)


def _decode_msec(epoch):
    return datetime.fromtimestamp(epoch / 1000, tz=UTC).replace(tzinfo=None)


def _str_msec(dt):
    dt = _to_naive_utc(dt)
    return f"{dt.strftime(ISO8601_FMT)}.{dt.microsecond // 1000:03d}"


def _encode_ntp(dt):
    tsf, tsi = math.modf(dt2epoch(dt))
    return int(((int(tsi) + NTP_EPOCH_TO_UNIX_EPOCH) << 32) + (tsf * 2**32))


def _decode_ntp(ntp):
    tsf = ntp & (2**32 - 1)
    tsi = (ntp >> 32) - NTP_EPOCH_TO_UNIX_EPOCH
    return datetime.fromtimestamp(tsi + tsf / 2**32, tz=UTC).replace(tzinfo=None)


def _str_usec(dt):
    dt = _to_naive_utc(dt)
    return f"{dt.strftime(ISO8601_FMT)}.{dt.microsecond:06d}"


_parse_sec = _parse_msec = _parse_usec = _parse_iso_dt


def _encode_ip(ipaddr):
    return ipaddr.packed


# Builtin type registry (RFC 7012 + RFC 9740)
_roottypes = [
    OctetArrayType("octetArray", 0),
    StructType("unsigned8", 1, "B"),
    StructType("unsigned16", 2, "H"),
    StructType("unsigned32", 3, "L"),
    StructType("unsigned64", 4, "Q"),
    StructType("signed8", 5, "b"),
    StructType("signed16", 6, "h"),
    StructType("signed32", 7, "l"),
    StructType("signed64", 8, "q"),
    StructType("float32", 9, "f", valparse=float),
    StructType("float64", 10, "d", valparse=float),
    StructType(
        "boolean",
        11,
        "B",
        valenc=_encode_smibool,
        valdec=_decode_smibool,
        valstr=_str_bool,
        valparse=_parse_bool,
    ),
    StructType("macAddress", 12, "6s"),
    OctetArrayType(
        "string",
        13,
        valenc=_encode_utf8,
        valdec=_decode_utf8,
        valstr=_identity,
        valparse=_identity,
    ),
    StructType(
        "dateTimeSeconds",
        14,
        "L",
        valenc=_encode_sec,
        valdec=_decode_sec,
        valstr=_str_sec,
        valparse=_parse_sec,
    ),
    StructType(
        "dateTimeMilliseconds",
        15,
        "Q",
        valenc=_encode_msec,
        valdec=_decode_msec,
        valstr=_str_msec,
        valparse=_parse_msec,
    ),
    StructType(
        "dateTimeMicroseconds",
        16,
        "Q",
        valenc=_encode_ntp,
        valdec=_decode_ntp,
        valstr=_str_usec,
        valparse=_parse_usec,
    ),
    StructType(
        "dateTimeNanoseconds",
        17,
        "Q",
        valenc=_encode_ntp,
        valdec=_decode_ntp,
        valstr=_str_usec,
        valparse=_parse_usec,
    ),
    StructType(
        "ipv4Address",
        18,
        "4s",
        valenc=_encode_ip,
        valdec=ip_address,
        valparse=ip_address,
    ),
    StructType(
        "ipv6Address",
        19,
        "16s",
        valenc=_encode_ip,
        valdec=ip_address,
        valparse=ip_address,
    ),
    StructType(
        "unsigned256",
        23,
        "32s",
        valenc=_make_int_encoder(32, signed=False),
        valdec=_make_int_decoder(signed=False),
    ),
]

_TypeForName = {ietype.name: ietype for ietype in _roottypes}


def use_integer_ipv4():
    """
    Use integers instead of ipaddress.IPv4Address to store IPv4 addresses.
    Changes behavior globally; should be called before using any IPFIX types.
    Designed for use with numpy arrays, to not require a Python object for
    storing IP addresses.
    """
    _roottypes[_IPV4_NUM] = StructType("ipv4Address", _IPV4_NUM, "L")
    _TypeForName["ipv4Address"] = _roottypes[_IPV4_NUM]


def use_ipaddress_ipv4():
    """Restore ipaddress.IPv4Address representation for ipv4Address."""
    _roottypes[_IPV4_NUM] = StructType(
        "ipv4Address",
        _IPV4_NUM,
        "4s",
        valenc=_encode_ip,
        valdec=ip_address,
        valparse=ip_address,
    )
    _TypeForName["ipv4Address"] = _roottypes[_IPV4_NUM]


def for_name(name):
    """
    Return an IPFIX type for a given type name

    :param name: the name of the type to look up
    :returns: IpfixType -- type instance for that name
    :raises: IpfixTypeError

    """
    try:
        return _TypeForName[name]
    except KeyError as exc:
        raise IpfixTypeError("no such type " + name) from exc


def decode_varlen(buf, offset, end=None):
    """Decode an IPFIX varlen encoded length; used internally by template."""
    limit = len(buf) if end is None else end
    if offset + _varlen1_st.size > limit:
        raise struct.error("varlen prefix extends past end of buffer")
    length = _varlen1_st.unpack_from(buf, offset)[0]
    offset += _varlen1_st.size
    if length == 255:
        if offset + _varlen2_st.size > limit:
            raise struct.error("extended varlen prefix extends past end of buffer")
        length = _varlen2_st.unpack_from(buf, offset)[0]
        offset += _varlen2_st.size
    return (length, offset)


def encode_varlen(buf, offset, length):
    """Encode an IPFIX varlen encoded length; used internally by template."""
    if length >= 255:
        _varlen1_st.pack_into(buf, offset, 255)
        offset += _varlen1_st.size
        _varlen2_st.pack_into(buf, offset, length)
        offset += _varlen2_st.size
    else:
        _varlen1_st.pack_into(buf, offset, length)
        offset += _varlen1_st.size
    return offset
