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

>>> for rec in msg.namedict_iterator():
...    print(sorted(rec.items()))
...
[('destinationIPv4Address', IPv4Address('10.5.6.7')), ('flowStartMilliseconds', datetime.datetime(2013, 6, 21, 12, 0)), ('packetDeltaCount', 27), ('sourceIPv4Address', IPv4Address('10.1.2.3'))]
[('destinationIPv4Address', IPv4Address('10.12.13.14')), ('flowStartMilliseconds', datetime.datetime(2013, 6, 21, 12, 0, 2)), ('packetDeltaCount', 33), ('sourceIPv4Address', IPv4Address('10.8.9.11'))]
[('flowStartMilliseconds', datetime.datetime(2013, 6, 21, 12, 0, 4)), ('myNewInformationElement', "Grüezi, Y'all")]

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
(datetime.datetime(2013, 6, 21, 12, 0), 27)
(datetime.datetime(2013, 6, 21, 12, 0, 2), 33)

Notice that the variable-length record written to the message are not returned 
by this iterator, since that record doesn't include a packetDeltaCount IE. 
The record is, however, still there:

>>> ielist = ipfix.ie.spec_list(["myNewInformationElement"])
>>> for rec in msg.tuple_iterator(ielist):
...     print(rec)
...
("Grüezi, Y'all",)

"""

from . import template
from .template import IpfixEncodeError, IpfixDecodeError

import operator
import functools
import struct
from datetime import datetime
from warnings import warn

_sethdr_st = struct.Struct("!HH")
_msghdr_st = struct.Struct("!HHLLL")

class EndOfMessage(Exception):
    """
    Exception raised when a write operation on a Message
    fails because there is not enough space in the message.
    
    """
    def __init__(self, *args):
        super().__init__(args)

def accept_all_templates(tmpl):
    return True    

class MessageBuffer:
    """
    Implements a buffer for reading or writing IPFIX messages.
    
    """
    def __init__(self):
        """Create a new MessageBuffer instance."""
        self.mbuf = memoryview(bytearray(65536))

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
        
        self.mtu = 65535
        
    def __repr__(self):
        if self.cursetid:
            addinf = " (writing set "+str(self.cursetid)+")"
        elif self.setlist:
            addinf = " (deframed "+str(len(self.setlist))+" sets)"
        elif self.length:
            addinf = " (writing)"
        else:
            addinf = ""
        
        return "<MessageBuffer domain "+str(self.odid)+\
               " length "+str(self.length)+addinf+">"
        
    def get_export_time(self):
        """
        Return the export time of this message. When reading, returns the 
        export time as read from the message header. When writing, this is 
        the argument of the last call to :meth:`set_export_time`, or, if 
        :attr:auto_export_time is True, the time of the last message
        export.
        
        :returns: export time of the last message read/written.
        
        """
        return datetime.utcfromtimestamp(self.export_epoch)

    def set_export_time(self, dt=None):
        """
        Set the export time for the next message written with 
        :meth:`write_message` or :meth:`to_bytes`. Disables automatic export 
        time updates. By default, sets the export time to the current time.
        
        :param dt: export time to set, as a datetime
        
        """
        if not dt:
            dt = datetime.utcnow()
        self.export_epoch = int(dt.timestamp())        
        self.auto_export_time = False
                
    def _increment_sequence(self):
        self.sequences.setdefault((self.odid, self.streamid), 0)
        self.sequences[(self.odid, self.streamid)] += 1
        
    def _scan_setlist(self):
        # We've read a message. Discard all export state.
        self.cursetoff = 0
        self.cursetid = None
        self.curtmpl = None        
        
        # Clear the setlist and start from the beginning of the body
        self.setlist.clear()
        offset = _msghdr_st.size
        
        while (offset < self.length):
            (setid, setlen) = _sethdr_st.unpack_from(self.mbuf, offset)
            if offset + setlen > self.length:
                raise IPFIXDecodeError("Set too long for message")
            self.setlist.append((offset, setid, setlen))
            offset += setlen
    
    def read_message(self, stream):
        """Read a IPFIX message from a stream.
        
        This populates message header fields and the internal setlist.
        Call for each new message before iterating over records when reading
        from a stream.
        
        :param stream: stream to read from
        :raises: IpfixDecodeError
        
        """
        
        # deframe and parse message header 
        msghdr = stream.read(_msghdr_st.size)
        if (len(msghdr) == 0):
            raise EOFError()
        elif (len(msghdr) < _msghdr_st.size):
            raise IpfixDecodeError("Short read in message header ("+ 
                                       str(len(msghdr)) +")")

        self.mbuf[0:_msghdr_st.size] = msghdr
        (version, self.length, self.sequence, self.export_epoch, self.odid) = \
                _msghdr_st.unpack_from(self.mbuf, 0)
        
        # verify version and length
        if version != 10:
            raise IpfixDecodeError("Illegal or unsupported version " + 
                                       str(version))
        
        if self.length < 20:
            raise IpfixDecodeError("Illegal message length" + 
                                       str(self.length))
            
        # read the rest of the message into the buffer
        msgbody = stream.read(self.length-_msghdr_st.size)
        if len(msgbody) < self.length - _msghdr_st.size:
            raise IpfixDecodeError("Short read in message body (got "+
                                   str(len(msgbody))+", expected "+
                                   str(self.length - _msghdr_st.size)+")")
        self.mbuf[_msghdr_st.size:self.length] = msgbody
        
        # populate setlist
        self._scan_setlist()
            
    def from_bytes(self, bytes):
        """Read an IPFIX message from a byte array.
        
        This populates message header fields and the internal setlist.
        Call for each new message before iterating over records when reading
        from a byte array.        

        :param bytes: a byte array containing a complete IPFIX message.
        :raises: IpfixDecodeError
        
        """
        # make a copy of the byte array
        self.mbuf[0:len(bytes)] = bytes

        # parse message header 
        if (len(bytes) < _msghdr_st.size):
            raise IpfixDecodeError("Message too short ("+str(len(msghdr)) +")")

        (version, self.length, self.sequence, self.export_epoch, self.odid) = \
                _msghdr_st.unpack_from(self.mbuf, 0)
        
        # verify version and length
        if version != 10:
            raise IpfixDecodeError("Illegal or unsupported version " + 
                                   str(version))
        
        if self.length < 20:
            raise IpfixDecodeError("Illegal message length" + str(self.length))
        
        # populate setlist
        self._scan_setlist()
            
    def record_iterator(self, 
                        decode_fn=template.Template.decode_namedict_from, 
                        tmplaccept_fn=accept_all_templates, 
                        recinf=None):
        """
        Low-level interface to record iteration.
        
        Iterate over records in an IPFIX message previously read with 
        :meth:`read_message()` or :meth:`from_bytes()`. Automatically handles 
        templates in set order. By default, iterates over each record in the 
        stream as a dictionary mapping IE name to value 
        (i.e., the same as :meth:`namedict_iterator`)
        
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
        for (offset, setid, setlen) in self.setlist:
            setend = offset + setlen
            offset += _sethdr_st.size # skip set header in decode
            if setid == 2 or setid == 3:
                while offset < setend:
                    (tmpl, offset) = template.decode_template_from(
                                              self.mbuf, offset, setid)
                    # FIXME handle withdrawal
                    self.templates[(self.odid, tmpl.tid)] = tmpl
                    if tmplaccept_fn(tmpl):
                        self.accepted_tids.add((self.odid, tmpl.tid))
                    else:
                        self.accepted_tids.discard((self.odid, tmpl.tid))
                    
            elif setid < 256:
                warn("skipping illegal set id "+setid)
            elif (self.odid, setid) in self.accepted_tids:
                try:
                    tmpl = self.templates[(self.odid, setid)]
                    while offset + tmpl.minlength <= setend:
                        (rec, offset) = decode_fn(tmpl, self.mbuf, offset, 
                                                  recinf = recinf)
                        yield rec
                        self._increment_sequence()
                except KeyError:
                    #FIXME provide set buffer for sets without templates
                    pass
            else:
                #FIXME disable sequence checking on skipped sets
                pass

    def namedict_iterator(self):
        """
        Iterate over all records in the Message, as dicts mapping IE names
        to values.
        
        :returns: a name dictionary iterator
        
        """
        
        return self.record_iterator(
                decode_fn = template.Template.decode_namedict_from)
    
    def _recache_accepted_tids(self, tmplaccept_fn):
        for tid in self.active_template_ids():
            if tmplaccept_fn(self.templates[(self.odid, tid)]):
                self.accepted_tids.add((self.odid, tid))
            else:
                self.accepted_tids.discard((self.odid, tid))

    def tuple_iterator(self, ielist):
        """
        Iterate over all records in the Message containing all the IEs in 
        the given ielist. Records are returned as tuples in ielist order.
        
        :param ielist: an instance of :class:`ipfix.ie.InformationElementList`
                       listing IEs to return as a tuple
        :returns: a tuple iterator for tuples as in ielist order
        
        """
        
        tmplaccept_fn = lambda tmpl: \
                functools.reduce(operator.__and__, 
                                 (ie in tmpl.ies for ie in ielist))        

        if ((not self.last_tuple_iterator_ielist) or
            (ielist is not self.last_tuple_iterator_ielist)):
                self._recache_accepted_tids(tmplaccept_fn)
        self.last_tuple_iterator_ielist = ielist

        return self.record_iterator(
                decode_fn = template.Template.decode_tuple_from, 
                tmplaccept_fn = tmplaccept_fn, 
                recinf = ielist)          

    def to_bytes(self):
        """
        Convert this MessageBuffer to a byte array, suitable for writing
        to a binary file, socket, or datagram. Finalizes the message by
        rewriting the message header with current length, and export time. 
        
        :returns: message as a byte array
        
        """

        # Close final set 
        self._export_close_set()
        
        # Update export time if necessary
        if self.auto_export_time:
            self.export_epoch = int(datetime.utcnow().timestamp())
        
        # Update message header in buffer
        _msghdr_st.pack_into(self.mbuf, 0, 10, self.length, 
                             self.sequence, self.export_epoch, self.odid)
    
        
        return self.mbuf[0:self.length].tobytes()

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
        if export:
            self.export_template(tmpl.tid)
    
    def delete_template(self, tid, export=True):
        """
        Delete a template by ID from this MessageBuffer.
        
        :param tid: ID of the template to delete
        :param export: if True, export a Template Withdrawal for this
                       Template after deleting it
        :raises: EndOfMessage
        
        """
        setid = self.templates[self.odid, tid].native_setid()
        del(self.templates[self.odid, tid])
        if export:
            self.export_template_withdrawal(setid, tid)

    def active_template_ids(self):
        """
        Get an iterator over all active template IDs in the current domain.
        Provided to allow callers to export some or all active Templates across
        multiple Messages.
        
        :returns: a template ID iterator
        
        """
        for tk in filter(lambda k: k[0] == self.odid, self.templates):
            yield tk[1]  
    
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
        self.setlist.clear()
        
        # Set sequence number
        self.sequences.setdefault((self.odid, self.streamid), 0) # FIXME why do we need this?
        self.sequence = self.sequences[(self.odid, self.streamid)]
        
        # set new domain if necessary
        if odid:
            self.odid = odid
        
        # reset message and zero header
        self.length = _msghdr_st.size
        self.cursetoff = self.length
        self.mbuf[0:_msghdr_st.size] = bytes([0] * _msghdr_st.size)
    
        if self.mtu <= self.length:
            raise IpfixEncodeError("MTU too small: "+str(self.mtu))
    
        # no current set
        self.cursetid = None
        
    def export_new_set(self, setid):
        """
        Start exporting a new Set with the given set ID. Creates a new set
        even if the current Set has the given set ID; client code should in most
        cases use :meth:`export_ensure_set` instead.
        
        :param setid: Set ID of the new Set; corresponds to the Template ID of
                      the Template that will be used to encode records into the
                      Set. The require Template must have already been added
                      to the MessageBuffer, see :meth:`add_template`.
        :raises: IpfixEncodeError, EndOfMessage
        
        """
        # close current set if any
        self._export_close_set()

        if setid >= 256:
            # make sure we have a template for the set
            if not ((self.odid, setid) in self.templates):
                raise IpfixEncodeError("can't start set without template id " + 
                                       str(setid))

            # make sure we have room to export at least one record
            tmpl = self.templates[(self.odid, setid)]
            if self.length + _sethdr_st.size + tmpl.minlength > self.mtu:
                raise EndOfMessage()
        else:
            # special Set ID. no template
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
        Starts a new set if not using :meth:`export_new_set`
        
        :param setid: Set ID of the new Set; corresponds to the Template ID of
                      the Template that will be used to encode records into the
                      Set. The require Template must have already been added
                      to the MessageBuffer, see :meth:`add_template`.
        :raises: IpfixEncodeError, EndOfMessage
        
        """
        if self.cursetid != setid:
            self.export_new_set(setid)

    def export_needs_flush(self):
        """
        True if content has been written to this MessageBuffer since the
        last call to :meth:`begin_export`
        
        """
        if self.length <= _msghdr_st.size + _sethdr_st.size:
            return False
        else:
            return True

    def _export_close_set(self):
        if self.cursetid:
            _sethdr_st.pack_into(self.mbuf, self.cursetoff, 
                                 self.cursetid, self.length - self.cursetoff)
            self.cursetid = None
   
    def export_template(self, tid):
        """
        Export a template to this Message given its template ID.
        
        :param tid: ID of template to export; must have been added to this
                    message previously with :meth:`add_template`.
        :raises: EndOfMessage, KeyError
        
        """
        
        tmpl = self.templates[(self.odid, tid)]
        
        self.export_ensure_set(tmpl.native_setid())
        
        if self.length + tmpl.enclength > self.mtu:
            raise EndOfMessage
        
        self.length = tmpl.encode_template_to(self.mbuf, self.length, 
                                              tmpl.native_setid())

    def _export_template_withdrawal(self, setid, tid):
        self.export_ensure_set(setid)
        
        if self.length + template.withdrawal_length(setid) > self.mtu:
            raise EndOfMessage
        
        self.length = template.encode_withdrawal_to(self.mbuf, self.length, 
                                                    setid, tid)
    
    def export_record(self, rec, 
                      encode_fn=template.Template.encode_namedict_to, 
                      recinf = None):
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
        :param recinf: Record information opaquely passed to decode function
        :raises: EndOfMessage

        """
        savelength = self.length
        
        try:
            self.length = encode_fn(self.curtmpl, self.mbuf, self.length, rec, recinf)
        except struct.error: # out of bounds on the underlying mbuf 
            self.length = savelength
            raise EndOfMessage()
        
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
    
    def export_tuple(self, rec, ielist = None):
        """
        Export a record to the message, using the template for the current Set
        ID. The record is a tuple of values, in template order by default.
        If ielist is given, the tuple is in the order if IEs in that list
        instead. The tuple must contain one value for each IE in the template;
        values for IEs in the ielist not in the template will be ignored.
        
        :param rec: the record to export, as a tuple
        :param ielist: optional information element list describing the order
                       of the rec tuple
        :raises: EndOfMessage
        
        """       
        self.export_record(rec, template.Template.encode_tuple_to, ielist)