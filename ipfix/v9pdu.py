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
Provides the PduBuffer classes for read-only decoding of NetFlow v9 Protocol
Data Units (PDUs) from a stream or single packet.
"""

import struct
from warnings import warn

from . import ie, template, types
from .message import (
    _iter_template_set_records,
    _recache_all_accepted_tids,
    accept_all_templates,
)
from .template import IpfixDecodeError

NETFLOW9_VERSION = 9

_sethdr_st = struct.Struct("!HH")
_pduhdr_st = struct.Struct("!HHLLLL")


class PduBuffer:
    """
    Implements a buffer for reading NetFlow v9 PDUs from a stream or packet.

    Abstract base class; use :func:`from_stream` or :class:`SinglePduBuffer`.
    """

    def __init__(self, mbuf):
        """Create a new PduBuffer instance."""
        self.mbuf = mbuf

        self.length = 0
        self.cur = 0

        self.reccount = None
        self.sequence = None
        self.export_epoch = None
        self.sysuptime_ms = None
        self.basetime_epoch = None
        self.odid = 0
        self.sesid = 0

        self.templates = {}
        self.accepted_tids = set()
        self.sequences = {}

        self.last_tuple_iterator_ielist = None
        self._accepted_cache_key = None

        self.template_record_hook = None
        self.unknown_data_set_hook = None
        self.ignored_data_set_hook = None
        self.message_header_hook = None

    def __repr__(self):
        return f"<PduBuffer domain {self.odid} length {self.length}>"

    def _increment_sequence(self, inc=1):
        self.sequences[self.odid] = (self.sequences.get(self.odid, 0) + inc) & 0xFFFFFFFF

    def _parse_pdu_header(self):
        (
            version,
            self.reccount,
            self.sysuptime_ms,
            self.export_epoch,
            self.sequence,
            self.odid,
        ) = _pduhdr_st.unpack_from(self.mbuf, 0)

        if version != NETFLOW9_VERSION:
            raise IpfixDecodeError(f"Illegal or unsupported version {version}")

        self.basetime_epoch = self.export_epoch - (self.sysuptime_ms / 1000.0)
        if self.message_header_hook:
            self.message_header_hook(self)

    def set_iterator(self):
        """Low-level interface to set iteration."""
        while True:
            try:
                yield self.next_set()
            except EOFError:
                break

    def _iter_records(self, decode_fn, tmplaccept_fn, recinf):
        for mbuf, offset, setid, setlen in self.set_iterator():
            setend = offset + setlen
            setview = mbuf[:setend]
            offset += _sethdr_st.size  # skip set header in decode

            if setid in (template.V9_TEMPLATE_SET_ID, template.V9_OPTIONS_SET_ID):
                for tmpl in _iter_template_set_records(
                    mbuf, offset, setend, setid, v9=True
                ):
                    tkey = (self.sesid, self.odid, tmpl.tid)
                    self.templates[tkey] = tmpl
                    if tmplaccept_fn(tmpl):
                        self.accepted_tids.add(tkey)
                    else:
                        self.accepted_tids.discard(tkey)

                    if self.template_record_hook:
                        self.template_record_hook(self, tmpl)

            elif setid < 256:
                warn("skipping illegal set id " + str(setid), stacklevel=2)

            else:
                tkey = (self.sesid, self.odid, setid)
                try:
                    tmpl = self.templates[tkey]
                except KeyError:
                    if self.unknown_data_set_hook:
                        self.unknown_data_set_hook(
                            self, mbuf[offset - _sethdr_st.size : setend]
                        )
                    continue

                if tkey in self.accepted_tids:
                    if tmpl.minlength <= 0:
                        raise IpfixDecodeError(
                            f"Template {tmpl.tid} has zero minimum record length"
                        )
                    while offset + tmpl.minlength <= setend:
                        rec, offset = decode_fn(
                            tmpl, setview, offset, recinf=recinf
                        )
                        yield rec
                        self._increment_sequence()
                elif self.ignored_data_set_hook:
                    self.ignored_data_set_hook(
                        self, tmpl, mbuf[offset - _sethdr_st.size : setend]
                    )

    def record_iterator(
        self,
        decode_fn=template.Template.decode_namedict_from,
        tmplaccept_fn=accept_all_templates,
        recinf=None,
    ):
        """
        Low-level interface to record iteration.

        Iterate over records in a PDU stream or buffer. Automatically handles
        templates in set order. By default, iterates over each record as a
        dictionary mapping IE name to value (same as :meth:`namedict_iterator`).
        """
        if tmplaccept_fn is accept_all_templates:
            if self._accepted_cache_key != "all":
                self._recache_accepted_tids(accept_all_templates)
                self._accepted_cache_key = "all"
                self.last_tuple_iterator_ielist = None
        else:
            self._recache_accepted_tids(tmplaccept_fn)
            self._accepted_cache_key = None

        return self._iter_records(decode_fn, tmplaccept_fn, recinf)

    def namedict_iterator(self):
        """
        Iterate over all records in the PDU, as dicts mapping IE names to values.

        :returns: a name dictionary iterator
        """
        if self._accepted_cache_key != "all":
            self._recache_accepted_tids(accept_all_templates)
            self._accepted_cache_key = "all"
            self.last_tuple_iterator_ielist = None
        return self._iter_records(
            template.Template.decode_namedict_from, accept_all_templates, None
        )

    def active_template_ids(self):
        """
        Get an iterator over all active template IDs in the current session and domain.

        :returns: a template ID iterator
        """
        for sesid, odid, tid in self.templates:
            if sesid == self.sesid and odid == self.odid:
                yield tid

    def _recache_accepted_tids(self, tmplaccept_fn):
        _recache_all_accepted_tids(self.templates, self.accepted_tids, tmplaccept_fn)

    def tuple_iterator(self, ielist):
        """
        Iterate over all records in the PDU containing all the IEs in
        the given ielist. Records are returned as tuples in ielist order.

        :param ielist: an instance of :class:`ipfix.ie.InformationElementList`
                       listing IEs to return as a tuple
        :returns: a tuple iterator for tuples in ielist order
        """
        def tmplaccept_fn(tmpl):
            return all(elem in tmpl.ies for elem in ielist)

        cache_key = tuple(ielist)
        if self._accepted_cache_key != cache_key:
            self._recache_accepted_tids(tmplaccept_fn)
            self._accepted_cache_key = cache_key
        self.last_tuple_iterator_ielist = ielist

        return self._iter_records(
            template.Template.decode_tuple_from, tmplaccept_fn, ielist
        )

    def save_state(self):
        return {"t": self.templates.copy(), "s": self.sequences.copy()}

    def restore_state(self, state):
        for k, v in state["t"].items():
            self.templates[k] = v
        for k, v in state["s"].items():
            self.sequences[k] = v
        self._accepted_cache_key = None
        self.last_tuple_iterator_ielist = None


class StreamPduBuffer(PduBuffer):
    """Reads NetFlow v9 PDUs from a binary stream."""

    def __init__(self, stream, buf_sz=65536):
        super().__init__(mbuf=memoryview(bytearray(buf_sz)))
        self.stream = stream
        self._seen_pdu_header = False

    def next_set(self):
        """
        Reads the next set from the stream. Automatically reads PDU headers as
        well, since PDU headers are treated as a special case of set header in
        streamed PDU reading. Raises EOFError to signal end of stream.
        """
        sethdr = self.stream.read(_sethdr_st.size)
        if len(sethdr) == 0:
            raise EOFError()
        if len(sethdr) < _sethdr_st.size:
            raise IpfixDecodeError(f"Short read in V9 set header ({len(sethdr)})")

        self.mbuf[0 : _sethdr_st.size] = sethdr
        setid, setlen = _sethdr_st.unpack_from(self.mbuf)

        while setid == NETFLOW9_VERSION:
            restlen = _pduhdr_st.size - _sethdr_st.size
            resthdr = self.stream.read(restlen)
            if len(resthdr) < restlen:
                raise IpfixDecodeError(f"Short read in V9 pdu header ({len(resthdr)})")

            self.mbuf[_sethdr_st.size : _pduhdr_st.size] = resthdr
            self._parse_pdu_header()
            self._seen_pdu_header = True

            sethdr = self.stream.read(_sethdr_st.size)
            if len(sethdr) == 0:
                raise EOFError()
            if len(sethdr) < _sethdr_st.size:
                raise IpfixDecodeError(f"Short read in V9 set header ({len(sethdr)})")
            self.mbuf[0 : _sethdr_st.size] = sethdr
            setid, setlen = _sethdr_st.unpack_from(self.mbuf)

        if not self._seen_pdu_header:
            raise IpfixDecodeError(f"Illegal or unsupported version {setid}")

        if setlen < _sethdr_st.size or setlen > len(self.mbuf):
            raise IpfixDecodeError(f"Illegal V9 set length {setlen}")

        bodylen = setlen - _sethdr_st.size
        setbody = self.stream.read(bodylen)
        if len(setbody) < bodylen:
            raise IpfixDecodeError(f"Short read in V9 set body ({len(setbody)})")

        self.mbuf[_sethdr_st.size : setlen] = setbody
        self.length = setlen

        return (self.mbuf, 0, setid, setlen)


class SinglePduBuffer(PduBuffer):
    """Reads a single NetFlow v9 PDU from a bytes-like object."""

    def __init__(self, bytes_in):
        mv = memoryview(bytes_in)
        if len(mv) < _pduhdr_st.size:
            raise IpfixDecodeError(f"Short V9 PDU ({len(mv)} bytes)")
        super().__init__(mbuf=mv)
        self.length = len(mv)
        self._parse_pdu_header()
        self._next_set_ptr = _pduhdr_st.size

    def next_set(self):
        if self._next_set_ptr >= self.length:
            raise EOFError()
        if self._next_set_ptr + _sethdr_st.size > self.length:
            raise IpfixDecodeError("Truncated V9 set header")

        setloc = self._next_set_ptr
        setid, setlen = _sethdr_st.unpack_from(self.mbuf, setloc)
        if setlen < _sethdr_st.size:
            raise IpfixDecodeError(f"Illegal V9 set length {setlen}")
        if setloc + setlen > self.length:
            raise IpfixDecodeError("V9 set extends past end of PDU")

        self._next_set_ptr += setlen
        return (self.mbuf, setloc, setid, setlen)


def from_stream(stream, buf_sz=65536):
    """
    Get a StreamPduBuffer for a given stream.

    :param stream: stream to read
    :return: a :class:`StreamPduBuffer` wrapped around the stream.
    """
    return StreamPduBuffer(stream, buf_sz=buf_sz)


class TimeAdapter:
    """
    Wraps around a PduBuffer and adds flowStartMilliseconds and
    flowEndMilliseconds Information Elements to each record, turning
    the basetime-dependent timestamps common in V9 export into
    absolute timestamps.

    To use, create a PduBuffer, create a TimeAdapter with the PduBuffer
    as the constructor argument, then iterate tuples or namedicts from
    the TimeAdapter.
    """

    def __init__(self, pdubuf):
        self.pdubuf = pdubuf

    def _sysuptime_to_dt(self, sysuptime_ms):
        return types._decode_msec(self.pdubuf.basetime_epoch * 1000.0 + sysuptime_ms)

    def namedict_iterator(self):
        for rec in self.pdubuf.namedict_iterator():
            if "flowStartSysUpTime" in rec:
                rec["flowStartMilliseconds"] = self._sysuptime_to_dt(
                    rec["flowStartSysUpTime"]
                )
            if "flowEndSysUpTime" in rec:
                rec["flowEndMilliseconds"] = self._sysuptime_to_dt(
                    rec["flowEndSysUpTime"]
                )
            yield rec

    def tuple_iterator(self, ielist):
        flow_start = ie.for_spec("flowStartSysUpTime")
        flow_end = ie.for_spec("flowEndSysUpTime")

        if flow_start in ielist and flow_end in ielist:
            start_index = ielist.index(flow_start)
            end_index = ielist.index(flow_end)

            for rec in self.pdubuf.tuple_iterator(ielist):
                start_ms = self._sysuptime_to_dt(rec[start_index])
                end_ms = self._sysuptime_to_dt(rec[end_index])
                yield rec + (start_ms, end_ms)
        else:
            yield from self.pdubuf.tuple_iterator(ielist)
