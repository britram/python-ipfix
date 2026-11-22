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
Provides the MessageBuffer class for encoding and decoding IPFIX Messages.

This interface allows direct control over Messages; for reading or writing
records automatically from/to streams, see :mod:`ipfix.reader` and
:mod:`ipfix.writer`, respectively.

To create a message buffer:

>>> import ipfix.message
>>> msg = ipfix.message.MessageBuffer()
>>> msg
<MessageBuffer domain 0 length 0>

To prepare the buffer to write records:

>>> msg.begin_export(8304)
>>> msg
<MessageBuffer domain 8304 length 16 (writing)>

Note that the buffer grows to contain the message header.

To write records to the buffer, first you'll need a template:

>>> import ipfix.ie
>>> ipfix.ie.use_iana_default()
>>> import ipfix.template
>>> tmpl = ipfix.template.from_ielist(256,
...        ipfix.ie.spec_list(("flowStartMilliseconds",
...                            "sourceIPv4Address",
...                            "destinationIPv4Address",
...                            "packetDeltaCount")))
>>> tmpl
<Template ID 256 count 4 scope 0>

To add the template to the message:

>>> msg.add_template(tmpl)
>>> msg
<MessageBuffer domain 8304 length 40 (writing set 2)>

Note that :meth:`MessageBuffer.add_template` exports the template when it
is written by default, and that the current set ID is 2 (template set).

Now, a set must be created to add records to the message; the set ID must match
the ID of the template. MessageBuffer automatically uses the template matching
the set ID for record encoding.

>>> msg.export_ensure_set(256)
>>> msg
<MessageBuffer domain 8304 length 44 (writing set 256)>

Records can be added to the set either as dictionaries keyed by IE name:

>>> from datetime import datetime
>>> from ipaddress import ip_address
>>> rec = { "flowStartMilliseconds" : datetime.strptime("2013-06-21 14:00:00",
...                                       "%Y-%m-%d %H:%M:%S"),
...         "sourceIPv4Address" : ip_address("10.1.2.3"),
...         "destinationIPv4Address" : ip_address("10.5.6.7"),
...         "packetDeltaCount" : 27 }
>>> msg.export_namedict(rec)
>>> msg
<MessageBuffer domain 8304 length 68 (writing set 256)>

or as tuples in template order:

>>> rec = (datetime.strptime("2013-06-21 14:00:02", "%Y-%m-%d %H:%M:%S"),
...        ip_address("10.8.9.11"), ip_address("10.12.13.14"), 33)
>>> msg.export_tuple(rec)
>>> msg
<MessageBuffer domain 8304 length 92 (writing set 256)>

Variable-length information elements will be encoded using the native length
of the passed value:

>>> ipfix.ie.for_spec("myNewInformationElement(35566/1)<string>")
InformationElement('myNewInformationElement', 35566, 1, ipfix.types.for_name('string'), 65535)
>>> tmpl = ipfix.template.from_ielist(257,
...        ipfix.ie.spec_list(("flowStartMilliseconds",
...                            "myNewInformationElement")))
>>> msg.add_template(tmpl)
>>> msg.export_ensure_set(257)
>>> msg
<MessageBuffer domain 8304 length 116 (writing set 257)>
>>> rec = { "flowStartMilliseconds" : datetime.strptime("2013-06-21 14:00:04",
...                                   "%Y-%m-%d %H:%M:%S"),
...         "myNewInformationElement" : "Grüezi, Y'all" }
>>> msg.export_namedict(rec)
>>> msg
<MessageBuffer domain 8304 length 139 (writing set 257)>

Attempts to write past the end of the message (set via the mtu parameter,
default 65535) result in :exc:`EndOfMessage` being raised.

Messages can be written to a stream using :meth:`MessageBuffer.write_message`,
or dumped to a byte array for transmission using :meth:`MessageBuffer.to_bytes`.
The message must be reset before starting to write again.

>>> b = msg.to_bytes()
>>> msg.begin_export()
>>> msg
<MessageBuffer domain 8304 length 16 (writing)>

Reading happens more or less in reverse. To begin, a message is read from a
byte array using :meth:`MessageBuffer.from_bytes`, or from a stream using
:meth:`MessageBuffer.read_message`.

>>> msg.from_bytes(b)
>>> msg
<MessageBuffer domain 8304 length 139 (deframed 4 sets)>

Both of these methods scan the message in advance to find the sets within
the message. The records within these sets can then be accessed by iterating
over the message. As with export, the records can be accessed as a dictionary
mapping IE names to values or as tuples. The dictionary interface is
designed for general IPFIX processing applications, such as collectors
accepting many types of data, or diagnostic tools for debugging IPFIX export:

>>> def print_msg(msg):
...     for rec in msg.namedict_iterator():
...         key = 'myNewInformationElement'
...         if key in rec:
...             unicode_recs = [(key, rec[key])]
...             recs = [item for item in sorted(rec.items()) if item[0] != key]
...         else:
...             unicode_recs = []
...             recs = sorted(rec.items())
...         print(recs)
...         for key, value in unicode_recs:
...             print("{}: {}".format(key, value))
...
>>> print_msg(msg)
[('destinationIPv4Address', IPv4Address('10.5.6.7')), ('flowStartMilliseconds', datetime.datetime(2013, 6, 21, 14, 0)), ('packetDeltaCount', 27), ('sourceIPv4Address', IPv4Address('10.1.2.3'))]
[('destinationIPv4Address', IPv4Address('10.12.13.14')), ('flowStartMilliseconds', datetime.datetime(2013, 6, 21, 14, 0, 2)), ('packetDeltaCount', 33), ('sourceIPv4Address', IPv4Address('10.8.9.11'))]
[('flowStartMilliseconds', datetime.datetime(2013, 6, 21, 14, 0, 4))]
myNewInformationElement: Grüezi, Y'all

The tuple interface for reading messages is designed for applications with a
specific internal data model. It can be much faster than the dictionary
interface, as it skips decoding of IEs not requested by the caller, and can
skip entire sets not containing all the requested IEs. Requested IEs are
specified as an :class:`ipfix.ie.InformationElementList` instance, from
:func:`ie.spec_list()`:

>>> ielist = ipfix.ie.spec_list(["flowStartMilliseconds", "packetDeltaCount"])
>>> for rec in msg.tuple_iterator(ielist):
...     print(rec)
...
(datetime.datetime(2013, 6, 21, 14, 0), 27)
(datetime.datetime(2013, 6, 21, 14, 0, 2), 33)

Notice that the variable-length record written to the message is not returned
by this iterator, since that record doesn't include a packetDeltaCount IE.
The record is, however, still there:

>>> ielist = ipfix.ie.spec_list(["myNewInformationElement"])
>>> for rec in msg.tuple_iterator(ielist):
...     print(rec[0])
...
Grüezi, Y'all

"""

import io
import struct
from datetime import UTC, datetime
from warnings import warn

from . import template, types
from .template import EndOfMessage, IpfixDecodeError, IpfixEncodeError

_sethdr_st = struct.Struct("!HH")
_msghdr_st = struct.Struct("!HHLLL")


def accept_all_templates(tmpl):
    return True


def _is_zero_padding(buf, start, end):
    return all(b == 0 for b in buf[start:end])


def _iter_template_set_records(buf, offset, setend, setid, *, v9=False):
    setview = buf[:setend]
    label = "v9 template set" if v9 else "template set"
    while offset < setend:
        rem = setend - offset
        # RFC 7011 §3.3.1: alignment padding at end of Template Set
        if rem < template._tmplhdr_st.size:
            if _is_zero_padding(buf, offset, setend):
                break
            raise IpfixDecodeError(f"Non-zero trailing bytes ({rem}) in {label}")
        if (
            buf[offset] == 0
            and buf[offset + 1] == 0
            and _is_zero_padding(buf, offset, setend)
        ):
            break

        tmpl, offset = template.decode_template_from(
            setview, offset, setid, setend=setend
        )
        yield tmpl


def _recache_all_accepted_tids(templates, accepted_tids, tmplaccept_fn):
    accepted_tids.clear()
    for key, tmpl in templates.items():
        if tmplaccept_fn(tmpl):
            accepted_tids.add(key)


class MessageBuffer:
    """
    Implements a buffer for reading or writing IPFIX messages.
    """

    def __init__(self, buf_sz=65536):
        """Create a new MessageBuffer instance."""
        self.mbuf = memoryview(bytearray(buf_sz))
        self.length = 0
        self.sequence = None
        self.export_epoch = None
        self.odid = 0
        self.streamid = 0

        self.templates = {}
        self.accepted_tids = set()
        self.sequences = {}

        self.setlist = []

        self.auto_export_time = True
        self.cursetoff = 0
        self.cursetid = None
        self.curtmpl = None

        self.last_tuple_iterator_ielist = None
        self._accepted_cache_key = None

        self.mtu = min(65535, buf_sz)

        self.template_record_hook = None
        self.unknown_data_set_hook = None
        self.ignored_data_set_hook = None
        self.message_header_hook = None

    def __repr__(self):
        if self.cursetid:
            addinf = f" (writing set {self.cursetid})"
        elif self.setlist:
            addinf = f" (deframed {len(self.setlist)} sets)"
        elif self.length:
            addinf = " (writing)"
        else:
            addinf = ""

        return f"<MessageBuffer domain {self.odid} length {self.length}{addinf}>"

    def get_export_time(self):
        """
        Return the export time of this message. When reading, returns the
        export time as read from the message header. When writing, this is
        the argument of the last call to :meth:`set_export_time`, or, if
        :attr:`auto_export_time` is True, the time of the last message
        export.

        :returns: export time of the last message read/written.
        """
        return types._decode_sec(self.export_epoch)

    def set_export_time(self, dt=None):
        """
        Set the export time for the next message written with
        :meth:`write_message` or :meth:`to_bytes`. Disables automatic export
        time updates. By default, sets the export time to the current time.

        :param dt: export time to set, as a datetime (aware or naive UTC)
        """
        if dt is None:
            dt = datetime.now(UTC)
        self.export_epoch = types._encode_sec(dt)
        self.auto_export_time = False

    def _increment_sequence(self):
        key = (self.odid, self.streamid)
        self.sequences[key] = (self.sequences.get(key, 0) + 1) & 0xFFFFFFFF

    def _scan_setlist(self):
        # We've read a message. Discard all export state.
        self.cursetoff = 0
        self.cursetid = None
        self.curtmpl = None

        # Clear the setlist and start from the beginning of the body
        self.setlist = []
        offset = _msghdr_st.size

        while offset < self.length:
            if offset + _sethdr_st.size > self.length:
                raise IpfixDecodeError("Truncated set header at end of message")
            setid, setlen = _sethdr_st.unpack_from(self.mbuf, offset)
            if setlen < _sethdr_st.size:
                raise IpfixDecodeError(f"Illegal set length {setlen} (must be >= 4)")
            if offset + setlen > self.length:
                raise IpfixDecodeError("Set too long for message")
            self.setlist.append((offset, setid, setlen))
            offset += setlen

    def read_message(self, stream):
        """Read an IPFIX message from a stream.

        This populates message header fields and the internal setlist.
        Call for each new message before iterating over records when reading
        from a stream.

        :param stream: stream to read from
        :raises: IpfixDecodeError, EOFError
        """
        # deframe and parse message header
        msghdr = stream.read(_msghdr_st.size)
        if len(msghdr) == 0:
            raise EOFError()
        if len(msghdr) < _msghdr_st.size:
            raise IpfixDecodeError(f"Short read in message header ({len(msghdr)})")

        self.mbuf[0 : _msghdr_st.size] = msghdr
        (version, self.length, self.export_epoch, self.sequence, self.odid) = (
            _msghdr_st.unpack_from(self.mbuf, 0)
        )

        # verify version and length
        if version != 10:
            raise IpfixDecodeError(f"Illegal or unsupported version {version}")

        if self.length < 20 or self.length > len(self.mbuf):
            raise IpfixDecodeError(f"Illegal message length {self.length}")

        # read the rest of the message into the buffer
        bodylen = self.length - _msghdr_st.size
        msgbody = stream.read(bodylen)
        if len(msgbody) < bodylen:
            raise IpfixDecodeError(
                f"Short read in message body (got {len(msgbody)}, expected {bodylen})"
            )
        self.mbuf[_msghdr_st.size : self.length] = msgbody

        # call the message header hook
        if self.message_header_hook:
            self.message_header_hook(self)

        # populate setlist
        self._scan_setlist()

    def from_bytes(self, data):
        """
        Read an IPFIX message from a bytes-like object.

        This populates message header fields and the internal setlist.
        Call for each new message before iterating over records when reading
        from a byte array.

        :param data: a bytes-like object containing a complete IPFIX message.
        :raises: IpfixDecodeError
        """
        return self.read_message(io.BytesIO(data))

    def _handle_template_withdrawal(self, setid, tid):
        if tid == setid:
            # All-Templates Withdrawal (RFC 7011 §8.1)
            to_delete = [
                k
                for k, t in self.templates.items()
                if k[0] == self.odid and t.native_setid() == setid
            ]
            for k in to_delete:
                del self.templates[k]
                self.accepted_tids.discard(k)
        else:
            key = (self.odid, tid)
            self.templates.pop(key, None)
            self.accepted_tids.discard(key)

    def _iter_records(self, decode_fn, tmplaccept_fn, recinf):
        for offset, setid, setlen in self.setlist:
            setend = offset + setlen
            setview = self.mbuf[:setend]
            offset += _sethdr_st.size  # skip set header in decode
            if setid in (template.TEMPLATE_SET_ID, template.OPTIONS_SET_ID):
                for tmpl in _iter_template_set_records(
                    self.mbuf, offset, setend, setid, v9=False
                ):
                    if tmpl.count() == 0:
                        self._handle_template_withdrawal(setid, tmpl.tid)
                    else:
                        key = (self.odid, tmpl.tid)
                        self.templates[key] = tmpl
                        if tmplaccept_fn(tmpl):
                            self.accepted_tids.add(key)
                        else:
                            self.accepted_tids.discard(key)

                    if self.template_record_hook:
                        self.template_record_hook(self, tmpl)

            elif setid < 256:
                warn("skipping illegal set id " + str(setid), stacklevel=2)
            else:
                key = (self.odid, setid)
                try:
                    tmpl = self.templates[key]
                except KeyError:
                    if self.unknown_data_set_hook:
                        self.unknown_data_set_hook(
                            self, self.mbuf[offset - _sethdr_st.size : setend]
                        )
                    continue

                if key in self.accepted_tids:
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
                        self, tmpl, self.mbuf[offset - _sethdr_st.size : setend]
                    )

    def record_iterator(
        self,
        decode_fn=template.Template.decode_namedict_from,
        tmplaccept_fn=accept_all_templates,
        recinf=None,
    ):
        """
        Low-level interface to record iteration.

        Iterate over records in an IPFIX message previously read with
        :meth:`read_message()` or :meth:`from_bytes()`. Automatically handles
        templates in set order. By default, iterates over each record in the
        stream as a dictionary mapping IE name to value
        (i.e., the same as :meth:`namedict_iterator`).

        :param decode_fn: Function used to decode a record;
                          must be an (unbound) "decode" instance method of the
                          :class:`ipfix.template.Template` class.
        :param tmplaccept_fn: Function returning True if the given template
                              is of interest to the caller, False if not.
                              Default accepts all templates. Sets described by
                              templates for which this function returns False
                              will be skipped.
        :param recinf: Record information opaquely passed to decode function
        :returns: an iterator over records decoded by decode_fn.
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
        Iterate over all records in the Message, as dicts mapping IE names
        to values.

        :returns: a name dictionary iterator
        """
        if self._accepted_cache_key != "all":
            self._recache_accepted_tids(accept_all_templates)
            self._accepted_cache_key = "all"
            self.last_tuple_iterator_ielist = None
        return self._iter_records(
            template.Template.decode_namedict_from, accept_all_templates, None
        )

    def _recache_accepted_tids(self, tmplaccept_fn):
        _recache_all_accepted_tids(self.templates, self.accepted_tids, tmplaccept_fn)

    def tuple_iterator(self, ielist):
        """
        Iterate over all records in the Message containing all the IEs in
        the given ielist. Records are returned as tuples in ielist order.

        :param ielist: an instance of :class:`ipfix.ie.InformationElementList`
                       listing IEs to return as a tuple
        :returns: a tuple iterator for tuples as in ielist order
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

    def to_bytes(self):
        """
        Convert this MessageBuffer to a bytes object, suitable for writing
        to a binary file, socket, or datagram. Finalizes the message by
        rewriting the message header with current length and export time.

        :returns: message as bytes
        """
        # Close final set
        self._export_close_set()

        # Update export time if necessary
        if self.auto_export_time:
            self.export_epoch = int(datetime.now(UTC).timestamp())

        # Update message header in buffer
        _msghdr_st.pack_into(
            self.mbuf,
            0,
            10,
            self.length,
            self.export_epoch,
            self.sequence,
            self.odid,
        )

        return self.mbuf[0 : self.length].tobytes()

    def write_message(self, stream):
        """
        Convenience method to write a message to a stream; see :meth:`to_bytes`.
        """
        stream.write(self.to_bytes())

    def add_template(self, tmpl, export=True):
        """
        Add a template to this MessageBuffer. Adding a template makes it
        available for use for exporting records; see :meth:`export_new_set`.

        :param tmpl: the template to add
        :param export: If True, export this template to the MessageBuffer
                       after adding it.
        :raises: EndOfMessage
        """
        self.templates[(self.odid, tmpl.tid)] = tmpl
        self._accepted_cache_key = None

        if export:
            self.export_template(tmpl.tid)

        if self.template_record_hook:
            self.template_record_hook(self, tmpl)

    def delete_template(self, tid, export=True):
        """
        Delete a template by ID from this MessageBuffer.

        :param tid: ID of the template to delete
        :param export: if True, export a Template Withdrawal for this
                       Template before deleting it
        :raises: EndOfMessage, KeyError
        """
        key = (self.odid, tid)
        setid = self.templates[key].native_setid()
        if export:
            self._export_template_withdrawal(setid, tid)
        elif self.cursetid == tid:
            self._export_close_set()
        del self.templates[key]
        self.accepted_tids.discard(key)

    def active_template_ids(self):
        """
        Get an iterator over all active template IDs in the current domain.
        Provided to allow callers to export some or all active Templates across
        multiple Messages.

        :returns: a template ID iterator
        """
        for odid, tid in self.templates:
            if odid == self.odid:
                yield tid

    def template_for_id(self, tid):
        """
        Retrieve a Template for a given ID in the current domain.

        :param tid: template ID to get
        :returns: the template
        :raises: KeyError
        """
        return self.templates[(self.odid, tid)]

    def begin_export(self, odid=None):
        """
        Start exporting a new message. Clears any previous message content,
        but keeps template information intact. Sets the message sequence number.

        :param odid: Observation domain ID to use for export. By default, uses
                     the observation domain ID of the previous message. Note
                     that templates are scoped to observation domain, so
                     templates will need to be added after switching to a new
                     observation domain ID.
        :raises: IpfixEncodeError
        """
        # We're exporting. Clear setlist from any previously read message.
        self.setlist = []

        # Set new domain before looking up sequence number
        if odid is not None:
            self.odid = odid

        # Set sequence number for current domain/stream
        self.sequence = self.sequences.setdefault((self.odid, self.streamid), 0)

        # reset message and zero header
        self.length = _msghdr_st.size
        self.cursetoff = self.length
        self.mbuf[0 : _msghdr_st.size] = bytes(_msghdr_st.size)

        if self.mtu <= self.length:
            raise IpfixEncodeError("MTU too small: " + str(self.mtu))

        # no current set
        self.cursetid = None
        self.curtmpl = None

    def export_new_set(self, setid):
        """
        Start exporting a new Set with the given set ID. Creates a new set
        even if the current Set has the given set ID; client code should in most
        cases use :meth:`export_ensure_set` instead.

        :param setid: Set ID of the new Set; corresponds to the Template ID of
                      the Template that will be used to encode records into the
                      Set. The required Template must have already been added
                      to the MessageBuffer, see :meth:`add_template`.
        :raises: IpfixEncodeError, EndOfMessage
        """
        # close current set if any
        self._export_close_set()

        if setid >= 256:
            # make sure we have a template for the set
            if (self.odid, setid) not in self.templates:
                raise IpfixEncodeError(
                    "can't start set without template id " + str(setid)
                )

            # make sure we have room to export at least one record
            tmpl = self.templates[(self.odid, setid)]
            if self.length + _sethdr_st.size + tmpl.minlength > self.mtu:
                raise EndOfMessage()
        else:
            # special Set ID. no template
            if self.length + _sethdr_st.size > self.mtu:
                raise EndOfMessage()
            tmpl = None

        # set up new set
        self.cursetoff = self.length
        self.cursetid = setid
        self.curtmpl = tmpl
        _sethdr_st.pack_into(self.mbuf, self.length, setid, 0)
        self.length += _sethdr_st.size

    def export_ensure_set(self, setid):
        """
        Ensure that the current set for export has the given Set ID.
        Starts a new set if not using :meth:`export_new_set`.

        :param setid: Set ID of the new Set; corresponds to the Template ID of
                      the Template that will be used to encode records into the
                      Set. The required Template must have already been added
                      to the MessageBuffer, see :meth:`add_template`.
        :raises: IpfixEncodeError, EndOfMessage
        """
        if self.cursetid != setid:
            self.export_new_set(setid)

    def export_needs_flush(self):
        """
        True if content has been written to this MessageBuffer since the
        last call to :meth:`begin_export`.
        """
        return self.length > _msghdr_st.size + _sethdr_st.size

    def _export_close_set(self):
        if self.cursetid is not None:
            if self.length == self.cursetoff + _sethdr_st.size:
                self.length = self.cursetoff
            else:
                _sethdr_st.pack_into(
                    self.mbuf,
                    self.cursetoff,
                    self.cursetid,
                    self.length - self.cursetoff,
                )
            self.cursetid = None
            self.curtmpl = None

    def _effective_length_for_set(self, setid):
        if (
            self.cursetid is not None
            and self.cursetid != setid
            and self.length == self.cursetoff + _sethdr_st.size
        ):
            return self.cursetoff
        return self.length

    def export_template(self, tid):
        """
        Export a template to this Message given its template ID.

        :param tid: ID of template to export; must have been added to this
                    message previously with :meth:`add_template`.
        :raises: EndOfMessage, KeyError
        """
        tmpl = self.templates[(self.odid, tid)]
        setid = tmpl.native_setid()
        hdrlen = (
            template._otmplhdr_st.size
            if setid == template.OPTIONS_SET_ID
            else template._tmplhdr_st.size
        )
        sethdr_needed = 0 if self.cursetid == setid else _sethdr_st.size
        base_len = self._effective_length_for_set(setid)

        if base_len + sethdr_needed + hdrlen + tmpl.enclength > self.mtu:
            raise EndOfMessage()

        self.export_ensure_set(setid)
        self.length = tmpl.encode_template_to(self.mbuf, self.length, setid)

    def _export_template_withdrawal(self, setid, tid):
        sethdr_needed = 0 if self.cursetid == setid else _sethdr_st.size
        base_len = self._effective_length_for_set(setid)

        if base_len + sethdr_needed + template.withdrawal_length(setid) > self.mtu:
            raise EndOfMessage()

        self.export_ensure_set(setid)
        self.length = template.encode_withdrawal_to(
            self.mbuf, self.length, setid, tid
        )

    def export_record(
        self,
        rec,
        encode_fn=template.Template.encode_namedict_to,
        recinf=None,
    ):
        """
        Low-level interface to record export.

        Export a record to a MessageBuffer, using the template associated with
        the Set ID given to the most recent :meth:`export_new_set` or
        :meth:`export_ensure_set` call, and the given encode function. By
        default, the record is assumed to be a dictionary mapping IE names
        to values (i.e., the same as :meth:`export_namedict`).

        :param encode_fn: Function used to encode a record;
                          must be an (unbound) "encode" instance method of the
                          :class:`ipfix.template.Template` class.
        :param recinf: Record information opaquely passed to encode function
        :raises: EndOfMessage, IpfixEncodeError
        """
        if self.curtmpl is None:
            raise IpfixEncodeError("no active data set for record export")
        savelength = self.length

        try:
            self.length = encode_fn(
                self.curtmpl, self.mbuf, self.length, rec, recinf
            )
        except Exception:
            self.length = savelength
            raise

        # check for mtu overrun
        if self.length > self.mtu:
            self.length = savelength
            raise EndOfMessage()

        self._increment_sequence()

    def export_namedict(self, rec):
        """
        Export a record to the message, using the template for the current Set
        ID. The record is a dictionary mapping IE names to values. The
        dictionary must contain a value for each IE in the template. Keys in the
        dictionary not in the template will be ignored.

        :param rec: the record to export, as a dictionary
        :raises: EndOfMessage
        """
        self.export_record(rec, template.Template.encode_namedict_to)

    def export_tuple(self, rec):
        """
        Export a record to the message, using the template for the current Set
        ID. The record is a tuple of values in template order.

        :param rec: the record to export, as a tuple in template order.
        :raises: EndOfMessage
        """
        self.export_record(rec, template.Template.encode_tuple_to)
