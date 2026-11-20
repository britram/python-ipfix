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
Representation of IPFIX templates.
Provides template-based packing and unpacking of data in IPFIX messages.

For reading, templates are handled internally. For writing, use
:func:`from_ielist` to create a template.

See :mod:`ipfix.message` for examples.

"""

import struct

from . import ie, types


# Builtin exceptions
class IpfixEncodeError(Exception):
    """Raised on internal encoding errors, or if message MTU is too small"""


class IpfixDecodeError(Exception):
    """Raised when decoding a malformed IPFIX message"""


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


class TemplatePackingPlan:
    """
    Plan to pack/unpack a specific set of indices for a template.
    Used internally by Templates for efficient encoding and decoding.

    """

    def __init__(self, tmpl, indices):
        self.tmpl = tmpl
        self.indices = indices
        self.ranks = sorted(range(len(indices)), key=indices.__getitem__)
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
        return (
            f"<TemplatePackingPlan {self.tmpl!r} pack {self.st.format} "
            f"indices {' '.join(str(i) for i in self.indices)}>"
        )


class Template:
    """
    An IPFIX Template.

    A template is an ordered list of IPFIX Information Elements with an ID.

    """

    def __init__(self, tid=0, iterable=None, *, _allow_withdrawal_tid=False):
        if _allow_withdrawal_tid:
            if not (tid in (TEMPLATE_SET_ID, OPTIONS_SET_ID) or 256 <= tid <= 65535):
                raise ValueError("bad template ID " + str(tid))
        elif tid < 256 or tid > 65535:
            raise ValueError("bad template ID " + str(tid))

        self.tid = tid
        self.minlength = 0
        self.enclength = 0
        self.scopecount = 0
        self.varlenslice = None
        self.packplan = None
        self._packplan_cache = {}

        self.ies = []
        if iterable:
            if not isinstance(iterable, ie.InformationElementList):
                iterable = ie.InformationElementList(iterable)
            for elem in iterable:
                self.append(elem)

    def __repr__(self):
        return (
            f"<Template ID {self.tid} count {len(self.ies)} scope {self.scopecount}>"
        )

    def identical_to(self, other):
        """
        Determine if two templates are identical to each other.

        Two templates are considered identical if they contain the same
        IEs (with the same lengths) in the same order, and the same scope count.
        Template ID is not considered as part of the test for template identity.
        """
        return (
            self.scopecount == other.scopecount
            and len(self.ies) == len(other.ies)
            and all(
                (a.pen, a.num, a.length) == (b.pen, b.num, b.length)
                for a, b in zip(self.ies, other.ies, strict=True)
            )
        )

    def append(self, elem):
        """Append an IE to this Template."""
        self.ies.append(elem)

        if elem.length == types.VARLEN:
            self.minlength += 1
            if self.varlenslice is None:
                self.varlenslice = len(self.ies) - 1
        else:
            self.minlength += elem.length

        self.enclength += _iespec_st.size
        if elem.pen:
            self.enclength += _iepen_st.size

    def count(self):
        """Count IEs in this template."""
        return len(self.ies)

    def fixlen_count(self):
        """
        Count of fixed-length IEs in this template before the first
        variable-length IE; this is the size of the portion of the template
        which can be encoded/decoded efficiently.
        """
        if self.varlenslice is not None:
            return self.varlenslice
        return self.count()

    def finalize(self):
        """Compile a default packing plan. Called after append()ing all IEs."""
        self.packplan = TemplatePackingPlan(self, range(self.count()))

    def packplan_for_ielist(self, ielist):
        """
        Given a list of IEs, devise and cache a packing plan.
        Used by the tuple interfaces.
        """
        plan = self._packplan_cache.get(ielist)
        if plan is None:
            if len(self._packplan_cache) >= 32:
                self._packplan_cache.clear()
            plan = TemplatePackingPlan(self, [self.ies.index(elem) for elem in ielist])
            self._packplan_cache[ielist] = plan
        return plan

    def decode_from(self, buf, offset, packplan=None, setend=None):
        """Decodes a record into a list containing values in template order."""
        limit = len(buf) if setend is None else setend

        # use default packplan unless someone hacked us not to
        if not packplan:
            packplan = self.packplan

        if offset + packplan.st.size > limit:
            raise IpfixDecodeError("Data record extends past end of set")

        # decode fixed values
        try:
            vals = [
                f(v)
                for f, v in zip(
                    packplan.valdec, packplan.st.unpack_from(buf, offset), strict=True
                )
            ]
        except (struct.error, ValueError, UnicodeDecodeError) as exc:
            raise IpfixDecodeError(f"Failed to decode fixed record field: {exc}") from exc
        offset += packplan.st.size

        # short circuit on no varlen
        if self.varlenslice is None:
            return (vals, offset)

        # direct iteration over remaining IEs
        for i, elem in zip(
            range(self.varlenslice, self.count()),
            self.ies[self.varlenslice :],
            strict=True,
        ):
            length = elem.length
            if length == types.VARLEN:
                try:
                    length, offset = types.decode_varlen(buf, offset, end=limit)
                except struct.error as exc:
                    raise IpfixDecodeError(f"Truncated varlen prefix: {exc}") from exc
            if offset + length > limit:
                raise IpfixDecodeError(
                    f"Field {elem.name} (length {length}) extends past end of set"
                )
            if i in packplan.indices:
                try:
                    vals.append(elem.type.decode_single_value_from(buf, offset, length))
                except (struct.error, ValueError, UnicodeDecodeError) as exc:
                    raise IpfixDecodeError(
                        f"Failed to decode field {elem.name}: {exc}"
                    ) from exc
            offset += length

        return (vals, offset)

    def decode_namedict_from(self, buf, offset, recinf=None):
        """Decodes a record from a buffer into a dict keyed by IE name."""
        vals, offset = self.decode_from(buf, offset)
        return ({elem.name: v for elem, v in zip(self.ies, vals, strict=True)}, offset)

    def decode_tuple_from(self, buf, offset, recinf=None):
        """
        Decodes a record from a buffer into a tuple,
        ordered as the IEs in the InformationElementList given as recinf.
        """
        if recinf:
            packplan = self.packplan_for_ielist(recinf)
        else:
            packplan = self.packplan

        vals, offset = self.decode_from(buf, offset, packplan=packplan)

        # re-sort values in same order as packplan indices
        outvals = tuple(v for _, v in sorted(zip(packplan.ranks, vals, strict=True)))

        return (outvals, offset)

    def encode_to(self, buf, offset, vals, packplan=None):
        """Encodes a record from a sequence containing values in template order."""
        if not packplan:
            packplan = self.packplan

        # encode fixed values
        fixvals = [f(v) for f, v in zip(packplan.valenc, vals, strict=False)]
        packplan.st.pack_into(buf, offset, *fixvals)
        offset += packplan.st.size

        # shortcircuit no varlen
        if self.varlenslice is None:
            return offset

        # direct iteration over remaining IEs
        for i, elem, val in zip(
            range(self.varlenslice, self.count()),
            self.ies[self.varlenslice :],
            vals[self.varlenslice :],
            strict=True,
        ):
            if i in packplan.indices:
                if elem.length == types.VARLEN:
                    enc = elem.type.valenc(val)
                    offset = types.encode_varlen(buf, offset, len(enc))
                    if offset + len(enc) > len(buf):
                        raise struct.error("varlen field exceeds message buffer")
                    buf[offset : offset + len(enc)] = enc
                    offset += len(enc)
                else:
                    offset = elem.type.encode_single_value_to(val, buf, offset)

        return offset

    def encode_namedict_to(self, buf, offset, rec, recinf=None):
        """Encodes a record from a dict containing values keyed by IE name."""
        return self.encode_to(buf, offset, [rec[elem.name] for elem in self.ies])

    def encode_tuple_to(self, buf, offset, rec, recinf=None):
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
            raise IpfixEncodeError("bad template set id " + str(setid))

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
        return TEMPLATE_SET_ID


def withdrawal_length(setid):
    if setid == TEMPLATE_SET_ID:
        return _tmplhdr_st.size
    if setid == OPTIONS_SET_ID:
        return _otmplhdr_st.size
    raise IpfixEncodeError("bad template set id " + str(setid))


def encode_withdrawal_to(buf, offset, setid, tid):
    if setid == TEMPLATE_SET_ID:
        _tmplhdr_st.pack_into(buf, offset, tid, 0)
        offset += _tmplhdr_st.size
    elif setid == OPTIONS_SET_ID:
        _otmplhdr_st.pack_into(buf, offset, tid, 0, 0)
        offset += _otmplhdr_st.size
    else:
        raise IpfixEncodeError("bad template set id " + str(setid))

    return offset


def decode_template_from(buf, offset, setid, setend=None):
    """
    Decodes a template from a buffer.
    Decodes as a Template if setid is TEMPLATE_SET_ID (or V9_TEMPLATE_SET_ID),
    as an Options Template if setid is OPTIONS_SET_ID (or V9_OPTIONS_SET_ID).
    """
    limit = len(buf) if setend is None else setend

    if setid in (TEMPLATE_SET_ID, V9_TEMPLATE_SET_ID):
        if offset + _tmplhdr_st.size > limit:
            raise IpfixDecodeError("Truncated template header")
        tid, count = _tmplhdr_st.unpack_from(buf, offset)
        scopecount = 0
        offset += _tmplhdr_st.size
    elif setid in (OPTIONS_SET_ID, V9_OPTIONS_SET_ID):
        if offset + _otmplhdr_st.size > limit:
            raise IpfixDecodeError("Truncated options template header")
        tid, count, scopecount = _otmplhdr_st.unpack_from(buf, offset)
        offset += _otmplhdr_st.size
    else:
        raise IpfixDecodeError("bad template set id " + str(setid))

    is_withdrawal = count == 0 and setid in (TEMPLATE_SET_ID, OPTIONS_SET_ID)
    if is_withdrawal:
        if setid == OPTIONS_SET_ID and scopecount != 0:
            raise IpfixDecodeError(
                f"Options template withdrawal must have scope count 0, got {scopecount}"
            )
        try:
            tmpl = Template(tid, _allow_withdrawal_tid=True)
        except ValueError as exc:
            raise IpfixDecodeError(str(exc)) from exc
        tmpl.finalize()
        return (tmpl, offset)

    if setid == OPTIONS_SET_ID and (scopecount == 0 or scopecount > count):
        raise IpfixDecodeError(
            f"Illegal options template scope count {scopecount} for field count {count}"
        )

    try:
        tmpl = Template(tid)
    except ValueError as exc:
        raise IpfixDecodeError(str(exc)) from exc
    tmpl.scopecount = scopecount

    while count:
        if offset + _iespec_st.size > limit:
            raise IpfixDecodeError("Truncated IE specifier in template")
        num, length = _iespec_st.unpack_from(buf, offset)
        offset += _iespec_st.size
        if length == 0:
            raise IpfixDecodeError(f"Illegal zero field length for IE {num & 0x7FFF}")
        if num & 0x8000:
            if setid in (V9_TEMPLATE_SET_ID, V9_OPTIONS_SET_ID):
                raise IpfixDecodeError("Enterprise bit set in NetFlow v9 template")
            num &= 0x7FFF
            if offset + _iepen_st.size > limit:
                raise IpfixDecodeError("Truncated enterprise number in template")
            pen = _iepen_st.unpack_from(buf, offset)[0]
            offset += _iepen_st.size
        else:
            pen = 0
        try:
            tmpl.append(ie.for_template_entry(pen, num, length))
        except types.IpfixTypeError as exc:
            raise IpfixDecodeError(str(exc)) from exc
        count -= 1

    tmpl.finalize()

    return (tmpl, offset)


def from_ielist(tid, ielist, scopecount=0):
    tmpl = Template(tid, ielist)
    tmpl.scopecount = scopecount
    tmpl.finalize()
    return tmpl


def for_specs(tid, *specs, scopecount=0):
    """
    Create a template from a template ID and a list of IESpecs.

    :param tid: Template ID, must be between 256 and 65535.
    :param *specs: List of IESpecs
    :param scopecount: Optional scope field count for Options Templates
    :return: A new Template, ready to use for writing to a Message
    """
    return from_ielist(tid, ie.spec_list(specs), scopecount=scopecount)
