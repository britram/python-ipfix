import re
from datetime import datetime, timedelta
from ipaddress import ip_address
from struct import Struct
from functools import total_ordering

# precompiled module variables (parsers)
_iespec_re = re.compile('^([^\s\[\<\(]+)?(\(((\d+)\/)?(\d+)\))?(\<(\S+)\>)?(\[(\S+)\])?')

_sethdr_st = Struct("!HH")
_msghdr_st = Struct("!HHLLL")
_tmplhdr_st = Struct("!HH")
_otmplhdr_st = Struct("!HHH")
_iespec_st = Struct("!HH")
_iepen_st = Struct("!L")

# constants
Varlen = 65535

# Builtin exception

class IPFIXDecodeError(Exception):
    def __init__(self, *args):
        super().__init__(args)

# Builtin type implementation

class IpfixType:
    """docstring for IpfixType"""
    def __init__(self, name, num):
        self.name = name
        self.num = num
    
    def __str__(self):
        return "<%s>" % self.name
        
    def __repr__(self):
        return "_TypeForName[%s]" % repr(self.name)
        
    def length(self):
        return 0;
    
    def decode_value_from(self, buf, offset, length):
        raise NotImplementedException()
    
    def encode_value_to(self, val, buf, offset, length):
        raise NotImplementedException()    


class BytesType(IpfixType):
    """docstring for BytesType"""
    def __init__(self, name, num, length):
        super().__init__(name, num)
        self.length = length;
        
    def length(self):
        return self.length;
    
    def decode_value_from(self, buf, offset, length):
        return bytes(buf[offset:offset+length])
    
    def encode_value_to(self, val, buf, offset, length):
        buf[offset:offset+length] = val


class IpAddressType(BytesType):
    """docstring for IpfixType"""
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
    """docstring for PackType"""
    def __init__(self, name, num, packstr, *rletypes):
        super().__init__(name, num)
        self.st = Struct(packstr)
        self.rletypes = rletypes
    
    def length(self):
        return self.st.size
    
    def decode_value_from(self, buf, offset, length):
        if length == self.length():
            return st.unpack_from(buf, offset)
        else:
            for rletype in self.rletypes:
                if length == rletype.length():
                    return rletype.decode_value_from(buf, offset, length)
            raise ValueError("no RLE for type " + self.name + " length " + length)
    
    def encode_value_to(self, val, buf, offset, length):
        if length == self.length():
            return st.pack_into(buf, offset, val);
        else:
            for rletype in self.rletypes:
                if length == rletype.length():
                    return rletype.encode_value_to(val, buf, offset, length)
            raise ValueError("no RLE for type " + self.name + " length " + length)

class BooleanType(PackedType):
    """docstring for BooleanType"""
    def __init__(self, name, num):
        super().__init__(name, num, "!B")
    
    def decode_value_from(self, buf, offset, length):
        return super().decode_value_from(self, buf, offset, length) == 1
    
    def encode_value_to(self, val, buf, offset, length):
        if val:
            smibool = 1
        else:
            smibool = 2
        super().encode_value_to(self, smibool, buf, offset, length)

class EpochSecondsType(PackedType):
    """docstring for EpochSecondsType"""
    def __init__(self, name, num):
        super().__init__(name, num, "!L")
    
    def decode_value_from(self, buf, offset, length):
        return datetime.utcfromtimestamp(super().decode_value_from(self, buf, offset, length))
    
    def encode_value_to(self, val, buf, offset, length):
        super().encode_value_to(self, val.timestamp(), buf, offset, length)


class EpochMillisecondsType(PackedType):
    """docstring for EpochMillisecondsType"""
    def __init__(self, name, num):
        super().__init__(name, num, "!Q")
    
    def decode_value_from(self, buf, offset, length):
        val = super().decode_value_from(self, buf, offset, length)
        return datetime.utcfromtimestamp(val/1000) + timedelta(milliseconds = val % 1000)
    
    def encode_value_to(self, val, buf, offset, length):
         super().encode_value_to(self, 
                 val.timestamp() * 1000 + val.microseconds / 1000, 
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
_Type_dateTimeMilliseconds = EpochMillisecondsType("dateTimeSeconds", 0)
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

_ieForName = {}
_ieForNum = {}

def _register_ie(ie):
    _ieForName[ie.name] = ie
    _ieForNum[(ie.pen, ie.num)] = ie
    
    return ie
    
@total_ordering
class InformationElement:
    """Represents a typed IPFIX Information Element"""
    def __init__(self, name, pen, num, ietype, length):
        
        if name:
            self.name = name
        else: 
            self.name = "_ipfix_%u_%u" % (pen, num)

        self.pen = pen
        self.num = num
        self.type = ietype
        
        if length:
            self.length = length
        else:
            self.length = self.type.length()
        
    
    def __eq__(self, other):
        return ((self.pen, self.num) == (other.pen, other.num))
    
    def __lt__(self, other):
        return ((self.pen, self.num) < (other.pen, other.num))

    def __repr__(self):
        return "InformationElement(%s, %s, %s, %s, %s)" % (repr(self.name), 
               repr(self.pen), repr(self.num), repr(self.type), 
               repr(self.length))

    def __str__(self):
        return "%s(%u/%u)%s[%u]" % (self.name, self.pen, self.num, str(self.type), self.length)
    
    def for_length(self, length):
        if not length or length == self.length:
            return self
        else:
            return self.__class__(self.name, self.pen, self.num, self.type, length)

    @classmethod
    def for_spec(cls, spec):
        (name, pen, num, typename, length) = _iespec_re.match(spec).group(1,4,5,7,9)

        if not name and not pen and not num and not typename and not length:
            raise ValueError("unrecognized IE spec "+spec)
        
        if pen: 
            pen = int(pen)
        else:
            pen = 0
        
        if num:
            num = int(num)
        else:
            num = 0
        
        if length:
            length = int(length)
        else:
            length = 0
        
        if name and not pen and not num and name in _ieForName:
                # lookup in name registry
                return _ieForName[name].for_length(length)
        
        if num and (pen, num) in _ieForNum:
                # lookup in number registry
                return _ieForNum[(pen, num)].for_length(length)
        
        # try to create new registered IE
        if not typename:
            raise ValueError("Cannot create new IE without valid type")
        
        if typename not in _TypeForName:
            raise ValueError("unrecognized type name "+typename)
        
        ietype = _TypeForName[typename]
        return _register_ie(cls(name, pen, num, ietype, length))
     
    @classmethod
    def for_template_entry(cls, pen, num, length):
        if ((pen, num) in _ieForNum):
            return _ieForNum[(pen, num)].for_length(length)
        
        return _register_ie(cls(None, pen, num, _TypeForName["octetArray"], length))
    

class Template:
    """Represents an ordered list of IPFIX Information Elements with an ID"""
    def __init__(self, tid = 0):
        super(Template, self).__init__()
        self.ies = [];
        self.tid = tid;

    def __iter__(self):
        return ies.__iter__()

    def append(self, ie):
        self.ies.append(ie)
    
    # FIXME all record encode/decode stuff lives in template
    # we probably want a callback-based interface too
    
    def decode_dict_from(self, buf, offset):
        rec = {}
        for ie in ies:
            if (ie.length == Varlen):
                raise ValueError("no varlen support yet")
            else:
                length = ie.length
                
            rec[ie.name] = ie.type.decode_value_from(buf, offset, length)
            offset += length
        
        return (rec, offset)

    def encode_dict_to(self, rec, buf, offset):
        for ie in ies:
            if (ie.length == Varlen):
                raise ValueError("no varlen support yet")
            else:
                length = ie.length
            
            val = rec[ie.name]
            ie.type.encode_value_to(val, buf, offset, length)
            offset += length
            
        return offset
    
    @classmethod
    def decode_template_from(cls, buf, offset):
        (tid, count) = _tmplhdr_st.unpack_from(buf, offset);
        tmpl = cls(tid)
        offset += _tmplhdr_st.calclength()
        while count:
            (num, length) = _iespec_st.unpack_from(buf, offset)
            offset += _iespec_st.calclength()
            if num & 0x8000:
                num &= 0x7fff
                (pen) = _iepen_st.unpack_from(buf, offset)
                offset += _iespec_st.calclength()
            else:
                pen = 0
            tmpl.append(InformationElement.for_template_entry(pen, num, length))
            count -= 1

    def encode_template_to(self, buf, offset):
        _tmplhdr_st.pack_into(buf, offset, self.tid, len(self.ies))
        for ie in ies:
            if ie.pen:
                _iespec_st.pack_into(buf, offset, ie.num | 0x8000, ie.length)
                offset += _iespec_st.calclength()
                _iepen_st.pack_into(buf, offset, ie.pen)
                offset += _iepen_st.calclength()
            else: 
                _iespec_st.pack_into(buf, offset, ie.num, ie.length)
                offset += _iespec_st.calclength()

class MessageStreamReader:
    """docstring for MessageStreamReader"""
    def __init__(self, stream):
        self.stream = stream
        self.mbuf = bytearray(65536)
        self.length = 0
        self.sequence = None
        self.export_time = None
        self.domain_id = None
        self.setlist = []
        self.templates = {}
    
    """deframe message and find set offsets"""
    def deframe(self):
        # Start at the beginning
        offset = 0
        self.setlist.clear()
        
        # deframe and parse message header 
        self.mbuf[0:_msghdr_st.size] = self.stream.read(_msghdr_st.size)
        (version, self.length, self.sequence, self.export_time, self.domain_id) = _msghdr_st.unpack_from(self.mbuf, offset)
        offset += _msghdr_st.size
        
        # verify version and length
        if version != 10:
            raise IPFIXDecodeError("Illegal or unsupported version " + str(version))
        
        if self.length < 20:
            raise IPFIXDecodeError("Illegal message length" + str(self.length))
            
        # read the rest of the message into the buffer
        self.mbuf[offset:length-offset] = self.stream.read(length-offset)
        
        # iterate over message and built setlist
        while (offset < self.length):
            (setid, setlen) = _sethdr_st.unpack_from(self.mbuf, offset)
            if offset + setlen > self.length:
                raise IPFIXDecodeError("Set too long for message")
            self.setlist.append((offset, setid, setlen))
            offset += setlen

    def dict_iterator(self):
        
        try:
            while(True):
                self.deframe()
                for (offset, setid, setlen) in setlist:
                    if setid == 2:
                        pass
                    elif setid == 3:
                        pass
                    elif setid < 256:
                        # FIXME warn on this instead
                        raise IPFIXDecodeError("illegal set ID")
                    else:
                        pass
        except EOFError:
            return
                    
                    