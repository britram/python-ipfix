#
# python-ipfix (c) 2013 Brian Trammell.
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
Representation of IPFIX templates.
Provides template-based packing and unpacking of data in IPFIX messages.

For reading, templates are handled internally. For writing, use
:func:`from_ielist` to create a template.

See :mod:`ipfix.message` for examples.

"""
from . import ie, types, compat
from .compat import izip, xrange, lru_cache

import struct


# Builtin exceptions
class IpfixEncodeError(Exception):
    """Raised on internal encoding errors, or if message MTU is too small"""
    def __init__(self, *args):
        super(self.__class__, self).__init__(args)

class IpfixDecodeError(Exception):
    """Raised when decoding a malformed IPFIX message"""
    def __init__(self, *args):
        super(self.__class__, self).__init__(args)

# constants for v9
V9_TEMPLATE_SET_ID = 0
V9_OPTIONS_SET_ID = 1

# constants
TEMPLATE_SET_ID = 2
OPTIONS_SET_ID = 3

# template encoding/decoding structs
_tmplhdr_st = struct.Struct("!HH")
_otmplhdr_st = struct.Struct("!HHH")
_iespec_st = struct.Struct("!HH")
_iepen_st = struct.Struct("!L")

class TemplatePackingPlan(object):
    """
    Plan to pack/unpack a specific set of indices for a template.
    Used internally by Templates for efficient encoding and decoding.

    """
    def __init__(self, tmpl, indices):
        self.tmpl = tmpl
        self.indices = indices
        self.ranks = sorted(xrange(len(indices)), key=indices.__getitem__)
        self.valenc = []
        self.valdec = []

        packstring = "!"
        for i, t in enumerate(e.type for e in tmpl.ies):
            if i >= tmpl.fixlen_count():
                break
            if i in indices:
                packstring += t.stel
                self.valenc.append(t.valenc)
                self.valdec.append(t.valdec)
            else:
                packstring += t.skipel

        self.st = struct.Struct(packstring)

    def __repr__(self):
        return "<TemplatePackingPlan "+repr(self.tmpl) +\
                " pack " + str(self.st.format) +\
                " indices " + " ".join(str(i) for i in self.indices)+">"

class Template(object):
    """
    An IPFIX Template.

    A template is an ordered list of IPFIX Information Elements with an ID.

    """
    def __init__(self, tid = 0, iterable = None):
        if tid < 256 or tid > 65535:
            raise ValueError("bad template ID "+str(tid))

        self.tid = tid
        self.minlength = 0
        self.enclength = 0
        self.scopecount = 0
        self.varlenslice = None
        self.packplan = None

        self.ies = []
        if iterable:
            if not isinstance(iterable, ie.InformationElementList):
                iterable = ie.InformationElementList(iterable)
            for elem in iterable:
                self.append(elem)

    def __repr__(self):
        return "<Template ID "+str(self.tid)+" count "+ \
               str(len(self.ies))+" scope "+str(self.scopecount)+">"

    def identical_to(self, other):
        """
        Determine if two templates are identical to each other.

        Two templates are considered identical if they contain the same
        IEs in the same order, and the same scope count. Template ID
        is not considered as part of the test for template identity.
        """

        # FIXME this needs to check IE lengths as well
        return (self.ies == other.ies) and (self.scopecount == other.scopecount)

    def append(self, ie):
        """Append an IE to this Template"""
        self.ies.append(ie)

        if ie.length == types.VARLEN:
            self.minlength += 1
            if self.varlenslice is None:
                self.varlenslice = len(self.ies) - 1
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
        if self.varlenslice is not None:
            return self.varlenslice
        else:
            return self.count()

    def finalize(self):
        """Compile a default packing plan. Called after append()ing all IEs."""
        self.packplan = TemplatePackingPlan(self, xrange(self.count()))

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
        vals = [f(v) for f, v in izip(packplan.valdec, packplan.st.unpack_from(buf, offset))]
        offset += packplan.st.size

        # short circuit on no varlen
        if self.varlenslice is None:
            return (vals, offset)

        # direct iteration over remaining IEs
        for i, ie in izip(xrange(self.varlenslice, self.count()),
                         self.ies[self.varlenslice:]):
            length = ie.length
            if length == types.VARLEN:
                (length, offset) = types.decode_varlen(buf, offset)
            if i in packplan.indices:
                vals.append(ie.type.decode_single_value_from(
                                    buf, offset, length))
            offset += length

        return (vals, offset)

    def decode_namedict_from(self, buf, offset, recinf = None):
        """Decodes a record from a buffer into a dict keyed by IE name."""
        (vals, offset) = self.decode_from(buf, offset)
        return (dict(( k, v) for k,v in izip((ie.name for ie in self.ies), vals)), offset)

    def decode_tuple_from(self, buf, offset, recinf = None):
        """
        Decodes a record from a buffer into a tuple,
        ordered as the IEs in the InformationElementList given as recinf.

        """
        if recinf:
            packplan = self.packplan_for_ielist(recinf)
        else:
            packplan = self.packplan

        (vals, offset) = self.decode_from(buf, offset, packplan = packplan)

        outvals = tuple(v for i,v in sorted(izip(packplan.ranks, vals)))

        # re-sort values in same order as packplan indices
        return (outvals, offset)

    def encode_to(self, buf, offset, vals, packplan = None):
        """Encodes a record from a tuple containing values in template order"""

        # use default packplan unless someone hacked us not to
        if not packplan:
            packplan = self.packplan

        # encode fixed values
        fixvals = [f(v) for f,v in izip(packplan.valenc, vals)]
        packplan.st.pack_into(buf, offset, *fixvals)
        offset += packplan.st.size

        # shortcircuit no varlen
        if self.varlenslice is None:
            return offset

        # direct iteration over remaining IEs
        for i, ie, val in izip(xrange(self.varlenslice, self.count()),
                              self.ies[self.varlenslice:],
                              vals[self.varlenslice:]):
            if i in packplan.indices:
                #print("    encoding "+str(ie))
                if ie.length == types.VARLEN:
                    # FIXME this arrangement requires double-encode of varlen
                    # values, one to get the length, one to do the encode.
                    # Fixing this requires a rearrangement of type encoding
                    # though. For now we'll just say that if you're exporting
                    # varlen you get to put up with some inefficiency. :)
                    offset = types.encode_varlen(buf, offset,
                                                 len(ie.type.valenc(val)))
                offset = ie.type.encode_single_value_to(val, buf, offset)

        return offset

    def encode_namedict_to(self, buf, offset, rec, recinf = None):
        """Encodes a record from a dict containing values keyed by IE name"""
        return self.encode_to(buf, offset, [rec[ie.name] for ie in self.ies])

    def encode_tuple_to(self, buf, offset, rec, recinf = None):
        """
        Encodes a record from a tuple containing values ordered as the IEs
        in the template.

        """
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
    if (setid == TEMPLATE_SET_ID) or (setid == V9_TEMPLATE_SET_ID):
        (tid, count) = _tmplhdr_st.unpack_from(buf, offset);
        scopecount = 0
        offset += _tmplhdr_st.size
    elif (setid == OPTIONS_SET_ID) or (setid == V9_OPTIONS_SET_ID):
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

def from_ielist(tid, ielist):

    tmpl = Template(tid, ielist)

    tmpl.finalize()

    return tmpl

def for_specs(tid, *specs):
    """
    Create a template from a template ID and a list of IESpecs

    :param tid: Template ID, must be between 256 and 65535.
    :param *specs: List of IESpecs
    :return: A new Template, ready to use for writing to a Message

    """
    return from_ielist(tid, ie.spec_list(specs))
