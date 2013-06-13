"""
Representation of IPFIX templates.
Provides template-based packing and unpacking of data in IPFIX messages.

See ipfix.message for examples.

"""
from . import ie    
from . import types
from functools import lru_cache

import struct

# Builtin exceptions
class IpfixEncodeError(Exception):
    """Raised on internal encoding errors, or if message MTU is too small"""
    def __init__(self, *args):
        super().__init__(args)

class IpfixDecodeError(Exception):
    """Raised when decoding a malformed IPFIX message"""
    def __init__(self, *args):
        super().__init__(args)

from struct import Struct

# constants
TEMPLATE_SET_ID = 2
OPTIONS_SET_ID = 3

# template encoding/decoding structs
_tmplhdr_st = Struct("!HH")
_otmplhdr_st = Struct("!HHH")
_iespec_st = Struct("!HH")
_iepen_st = Struct("!L")

class TemplatePackingPlan:
    """
    Plan to pack/unpack a specific set of indices for a template.
    Used internally by Templates for efficient encoding and decoding.
    
    """
    def __init__(self, tmpl, indices):
        self.tmpl = tmpl
        self.indices = indices
        self.valenc = []
        self.valdec = []
        
        packstring = "!"
        for i, t in enumerate(e.type for e in tmpl.ies):
            if i in indices:
                packstring += t.stel
                self.valenc.append(t.valenc)
                self.valdec.append(t.valdec)
            else:
                packstring += t.skipel           
        
        # old less pretty revision here
        #for i in range(tmpl.fixlen_count()):
        #    if i in indices:
        #        packstring += tmpl.ies[i].type.stel
        #        self.valenc.append(tmpl.ies[i].type.valenc)
        #        self.valdec.append(tmpl.ies[i].type.valdec)
        #    else:
        #        packstring += tmpl.ies[i].type.skipel
        
        self.st = struct.Struct(packstring)

class Template:
    """
    An IPFIX Template.
    
    A template is an ordered list of IPFIX Information Elements with an ID.
    
    """
    def __init__(self, tid = 0, iterable = None):
        self.ies = ie.InformationElementList()
        self.tid = tid
        self.minlength = 0
        self.enclength = 0
        self.scopecount = 0
        self.varlenslice = None
        self.packplan = None

    def append(self, ie):
        """Append an IE to this Template"""
        self.ies.append(ie)

        if ie.length == types.VARLEN:
            self.minlength += 1
            if not self.varlenslice:
                self.varlenslice = len(ies) - 1
        else:
            self.minlength += ie.length

        self.enclength += _iespec_st.size
        if (ie.pen):
            self.enclength += _iepen_st.size

    def count(self):
        """Count IEs in this template"""
        return len(self.ies)

    def fixlen_count(self):
        """
        Count of fixed-length IEs in this template before the first
        variable-length IE; this is the size of the portion of the template
        which can be encoded/decoded efficiently.
        
        """
        if self.varlenslice:
            return self.varlenslice
        else:
            return self.count()

    def finalize(self):
        """Compile a default packing plan. Called after append()ing all IEs."""
        self.packplan = TemplatePackingPlan(self, range(self.fixlen_count()))

    @lru_cache(maxsize = 32)
    def packplan_for_ielist(self, ielist):
        """
        Given a list of IEs, devise and cache a packing plan.
        Used by the tuple interfaces.
        
        """
        return TemplatePackingPlan(self, [self.ies.index(ie) for ie in ielist])
    
    def decode_from(self, buf, offset, packplan = None):
        """Decodes a record into a tuple containing values in template order"""

        # use default packplan unless someone hacked us not to
        if not packplan:
            packplan = self.packplan
            
        # decode fixed values 
        vals = [f(v) for f, v in zip(packplan.valdec, packplan.st.unpack_from(buf, offset))]
        offset += packplan.st.size
                
        # short circuit on no varlen
        if not self.varlenslice:
            return (vals, offset)
        
        # direct iteration over remaining IEs
        for i, ie in zip(range(self.varlenslice, self.count()), self.ies[self.varlenslice:]):
            length = ie.length
            if length == types.VARLEN:
                (length, offset) = types.decode_varlen(buf, offset)
            if i in packplan.indices:
                vals.append(ie.type.valdec(ie.type.decode_single_value_from(buf, offset, length)))
            offset += length
            
        return (vals, offset)

    def decode_iedict_from(self, buf, offset, recinf = None):
        """Decodes a record from a buffer into a dict keyed by IE"""
        (vals, offset) = self.decode_from(buf, offset)
        return ({ k: v for k,v in zip((ie for ie in self.ies), vals)}, offset)

    def decode_namedict_from(self, buf, offset, recinf = None):
        """Decodes a record from a buffer into a dict keyed by IE name."""
        (vals, offset) = self.decode_from(buf, offset)
        return ({ k: v for k,v in zip((ie.name for ie in self.ies), vals)}, offset)
        
    def decode_tuple_from(self, buf, offset, recinf = None):
        """
        Decodes a record from a buffer into a tuple,
        ordered as the IEs in the InformationElementList given as recinf.

        """
        if recinf:
            packplan = self.packplan_for_ielist(recinf)
        else:
            packplan = self.packplan
            
        vals = self.decode_from(buf, offset, packplan = packplan)

        # re-sort values in same order as packplan indices
        return tuple(v for i,v in sorted(zip(packplan.indices, vals)))
        
    def encode_to(self, buf, offset, vals, packplan = None):
        """Encodes a record from a tuple containing values in template order"""
        
        # use default packplan unless someone hacked us not to
        if not packplan:
            packplan = self.packplan
        
        # encode fixed values
        fixvals = [f(v) for f,v in zip(packplan.valenc, vals)]
        packplan.st.pack_into(buf, offset, *fixvals)
        offset += packplan.st.size
        
        # short circuit on no varlen
        if not self.varlenslice:
            return offset

        # direct iteration over remaining IEs
        for i, ie, val in zip(range(self.varlenslice, self.count()),
                              ies[self.varlenslice:],
                              vals[self.varlenslice:]):
            if i in packplan.indices:
                if ie.length == types.VARLEN:
                    offset = types.encode_varlen(buf, offset, len(val))
                offset = ie.type.encode_single_value_to(val, buf, offset)
                
        return offset
    
    def encode_iedict_to(self, buf, offset, rec, recinf = None):
        """Encodes a record from a dict containing values keyed by IE"""
        return self.encode_to(buf, offset, (rec[ie] for ie in ies))
    
    def encode_namedict_to(self, buf, offset, rec, recinf = None):
        """Encodes a record from a dict containing values keyed by IE name"""
        return self.encode_to(buf, offset, (rec[ie.name] for ie in ies))
        
    def encode_tuple_to(self, buf, offset, rec, recinf = None):
        """
        Encodes a record from a tuple containing values
        ordered as the IEs in the InformationElementList given as recinf.
        If recinf is not given, assumes the tuple contains all
        IEs in the template in template order.
         
        """
        if recinf:
            sortrec = (v for i, v in sorted(zip(packplan.indices, rec)))
            return self.encode_to(buf, offset, sortrec,
                                  self.packplan_for_ielist(recinf))
        else:
            return self.encode_to(buf, offset, rec)
    
    def encode_template_to(self, buf, offset, setid):
        """
        Encodes the template to a buffer.
        Encodes as a Template if setid is TEMPLATE_SET_ID,
        as an Options Template if setid is OPTIONS_SET_ID.
        
        """
        if setid == TEMPLATE_SET_ID:
            _tmplhdr_st.pack_into(buf, offset, self.tid, self.count())
            offset += _tmplhdr_st.size
        elif setid == OPTIONS_SET_ID:
            _otmplhdr_st.pack_into(buf, offset, self.tid, self.count(), self.scopecount)
            offset += _otmplhdr_st.size
        else:
            raise IpfixEncodeError("bad template set id "+str(setid))
            
        for e in self.ies:
            if e.pen:
                _iespec_st.pack_into(buf, offset, e.num | 0x8000, e.length)
                offset += _iespec_st.size
                _iepen_st.pack_into(buf, offset, e.pen)
                offset += _iepen_st.size
            else: 
                _iespec_st.pack_into(buf, offset, e.num, e.length)
                offset += _iespec_st.size
        
        return offset
    
    def native_setid(self):
        if self.scopecount:
            return OPTIONS_SET_ID
        else:
            return TEMPLATE_SET_ID

def withdrawal_length(setid):
    if setid == TEMPLATE_SET_ID:
        return _tmplhdr_st.size
    elif setid == OPTIONS_SET_ID:
        return _otmplhdr_st.size
    else:
        return IpfixEncodeError("bad template set id "+str(setid))
        
def encode_withdrawal_to(buf, offset, setid, tid):
    if setid == TEMPLATE_SET_ID:
        _tmplhdr_st.pack_into(buf, offset, tid, 0)
        offset += _tmplhdr_st.size
    elif setid == OPTIONS_SET_ID:
        _otmplhdr_st.pack_into(buf, offset, tid, 0, 0)
        offset += _otmplhdr_st.size
    else:
        raise IpfixEncodeError("bad template set id "+str(setid))
    
    return offset
    
def decode_template_from(buf, offset, setid):
    """
    Decodes a template from a buffer.
    Decodes as a Template if setid is TEMPLATE_SET_ID,
    as an Options Template if setid is OPTIONS_SET_ID.
    
    """
    if setid == TEMPLATE_SET_ID:
        (tid, count) = _tmplhdr_st.unpack_from(buf, offset);
        scopecount = 0
        offset += _tmplhdr_st.size
    elif setid == OPTIONS_SET_ID:
        (tid, count, scopecount) = _otmplhdr_st.unpack_from(buf, offset);
        offset += _otmplhdr_st.size
    else:
        raise IpfixDecodeError("bad template set id "+str(setid))
        
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

    tmpl.finalize()

    return (tmpl, offset)
    
def from_iespec(tid, iespecs):
    tmpl = Template(tid)
    for iespec in iespecs:
        tmpl.append(ie.for_spec(iespec))
    
    tmpl.finalize()
    
    return tmpl
