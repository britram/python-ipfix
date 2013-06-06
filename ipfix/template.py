from . import ie    
from . import types
import struct

# Builtin exceptions
class IpfixEncodeError(Exception):
    def __init__(self, *args):
        super().__init__(args)

class IpfixDecodeError(Exception):
    def __init__(self, *args):
        super().__init__(args)

from struct import Struct

# constants
TemplateSetId = 2
OptionsTemplateSetId = 3

# template encoding/decoding structs
_tmplhdr_st = Struct("!HH")
_otmplhdr_st = Struct("!HHH")
_iespec_st = Struct("!HH")
_iepen_st = Struct("!L")

class Template:
    """Represents an ordered list of IPFIX Information Elements with an ID"""
    def __init__(self, tid = 0):
        self.ies = [];
        self.tid = tid;
        self.minlength = 0
        self.enclength = 0
        self.scopecount = 0
        self.varlenslice = None
        self.st = None
        self.valenc = None
        self.valdec = None
        
    def append(self, ie):
        self.ies.append(ie)

        if ie.length == types.Varlen:
            self.minlength += 1
            if not self.varlenslice:
                self.varlenslice = len(ies) - 1
        else:
            self.minlength += ie.length

        self.enclength += _iespec_st.size
        if (ie.pen):
            self.enclength += _iepen_st.size

    def count(self):
        return len(self.ies)

    def make_struct(self):
        if self.varlenslice:
            fixmax = self.varlenslice
        else:
            fixmax = self.count()
        
        self.st = struct.Struct("!"+"".join((ie.type.stel for ie in self.ies[0:fixmax])))
        
        self.valdec = [ie.type.valdec for ie in self.ies[0:fixmax]]
        self.valenc = [ie.type.valenc for ie in self.ies[0:fixmax]]
    
    def decode_all_from(self, buf, offset):
        """Decodes a record into a tuple containing values in template order"""
        # decode fixed values 
        vals = [f(v) for f, v in zip(self.valdec, self.st.unpack_from(buf, offset))]
        offset += self.st.size
                
        # short circuit on no varlen
        if not self.varlenslice:
            return (vals, offset)
        
        # direct iteration over remaining IEs
        for ie in ies[self.varlenslice:]:
            length = ie.length
            if length == types.Varlen:
                (length, offset) = types.decode_varlen(buf, offset)
            vals.append(ie.type.valdec(ie.type.decode_single_value_from(buf, offset, length)))
            offset += length
            
        return (vals, offset)

    def decode_iedict_from(self, buf, offset):
        (vals, offset) = self.decode_all_from(buf, offset)
        return ({ k: v for k,v in zip((ie for ie in self.ies), vals)}, offset)

    def decode_namedict_from(self, buf, offset):
        (vals, offset) = self.decode_all_from(buf, offset)
        return ({ k: v for k,v in zip((ie.name for ie in self.ies), vals)}, offset)
        
    def encode_all_to(self, vals, buf, offset):
        # encode fixed values
        self.st.pack_into(buf, offset, [f(v) for f,v in zip(self.valenc, vals)])
        offset += self.st.size
        
        # short circuit on no varlen
        if not self.varlenslice:
            return offset

        # slow iteration over remaining IEs
        for (ie,val) in zip(ies[self.varlenslice:], vals[self.varlenslice:]):
            if ie.length == types.Varlen:
                offset = types.encode_varlen(ie.length, buf, offset)
            offset = ie.type.encode_single_value_to(val, buf, offset)

        return offset
    
    def encode_iedict_to(self, rec, buf, offset):
        return self.encode_all_to([rec[ie] for ie in ies], buf, offset)
    
    def encode_namedict_to(self, rec, buf, offset):
        return self.encode_all_to([rec[ie.name] for ie in ies], buf, offset)
    
    def encode_template_to(self, buf, offset, setid):
        if setid == TemplateSetId:
            _tmplhdr_st.pack_into(buf, offset, self.tid, self.count())
            offset += _tmplhdr_st.size
        elif setid == OptionsTemplateSetId:
            _otmplhdr_st.pack_into(buf, offset, self.tid, self.count(), self.scopecount)
            offset += _otmplhdr_st.size
        else:
            raise IpfixEncodeException("bad template set id "+str(setid))
            
        for e in ies:
            if e.pen:
                _iespec_st.pack_into(buf, offset, e.num | 0x8000, e.length)
                offset += _iespec_st.size
                _iepen_st.pack_into(buf, offset, e.pen)
                offset += _iepen_st.size
            else: 
                _iespec_st.pack_into(buf, offset, ie.num, e.length)
                offset += _iespec_st.size
        
        return offset
    
def decode_template_from(setid, buf, offset):
    if setid == TemplateSetId:
        (tid, count) = _tmplhdr_st.unpack_from(buf, offset);
        scopecount = 0
        offset += _tmplhdr_st.size
    elif setid == OptionsTemplateSetId:
        (tid, count, scopecount) = _otmplhdr_st.unpack_from(buf, offset);
        offset += _otmplhdr_st.size
        
    tmpl = Template(tid)
    tmpl.scopecount = scopecount
    
    while count:
        (num, length) = _iespec_st.unpack_from(buf, offset)
        offset += _iespec_st.size
        if num & 0x8000:
            num &= 0x7fff
            pen = _iepen_st.unpack_from(buf, offset)[0]
            offset += _iespec_st.size
        else:
            pen = 0
        tmpl.append(ie.for_template_entry(pen, num, length))
        count -= 1

    tmpl.make_struct()

    return (tmpl, offset)
    
def template_from_iespec(tid, iespecs):
    tmpl = Template(tid)
    for iespec in iespecs:
        tmpl.append(ie.for_name)
    
    tmpl.make_struct()
    
    return tmpl
