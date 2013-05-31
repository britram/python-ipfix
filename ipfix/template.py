from . import ie    
from . import types

from struct import Struct

_tmplhdr_st = Struct("!HH")
_otmplhdr_st = Struct("!HHH")
_iespec_st = Struct("!HH")
_iepen_st = Struct("!L")

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
    
    # all record encode/decode stuff lives in template
    # FIXME we probably want a callback-based interface too
    
    def decode_dict_from(self, buf, offset):
        rec = {}
        for e in ies:
            if (e.length == types.Varlen):
                raise ValueError("no varlen support yet")
            else:
                length = e.length
                
            rec[e.name] = e.type.decode_value_from(buf, offset, length)
            offset += length
        
        return (rec, offset)

    def encode_dict_to(self, rec, buf, offset):
        for e in ies:
            if (e.length == Varlen):
                raise ValueError("no varlen support yet")
            else:
                length = e.length
            
            val = rec[ie.name]
            e.type.encode_value_to(val, buf, offset, length)
            offset += length
            
        return offset
    

    def encode_template_to(self, buf, offset):
        _tmplhdr_st.pack_into(buf, offset, self.tid, len(self.ies))
        for e in ies:
            if e.pen:
                _iespec_st.pack_into(buf, offset, e.num | 0x8000, e.length)
                offset += _iespec_st.calclength()
                _iepen_st.pack_into(buf, offset, e.pen)
                offset += _iepen_st.calclength()
            else: 
                _iespec_st.pack_into(buf, offset, ie.num, e.length)
                offset += _iespec_st.calclength()

def decode_from_buffer(buf, offset):
    (tid, count) = _tmplhdr_st.unpack_from(buf, offset);
    tmpl = Template(tid)
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
        tmpl.append(ie.for_template_entry(pen, num, length))
        count -= 1

def from_iespecs(tid, iespecs):
    tmpl = Template(tid)
    for iespec in iespecs:
        tmpl.append(ie.for_name)
        