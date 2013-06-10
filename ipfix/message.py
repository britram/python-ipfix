"""
Provides the MessageBuffer class for encoding and decoding IPFIX messages.

This interface allows direct control over Messages; for reading or writing
records automatically, see ipfix.reader and ipfix.writer, respectively.

"""


from . import template

import operator
import functools
import struct
from datetime import datetime
from warnings import warn

_sethdr_st = struct.Struct("!HH")
_msghdr_st = struct.Struct("!HHLLL")

class EndOfMessage(Exception):
    """Raised when a write operation on a Message"""
    def __init__(self, *args):
        super().__init__(args)

def accept_all_templates(tmpl):
    return True    

class MessageBuffer:
    """Implements a buffer for reading or writing IPFIX messages"""
    def __init__(self):
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
        self.cursetid = 0
        self.curtmpl = None
        
        self._mtu = 65535
            
    def get_export_time(self):
        return datetime.utcfromtimestamp(self.export_epoch)

    def set_export_time(self, dt=datetime.utcnow()):
        self.export_epoch = int(dt.timestamp())        
        self.auto_export_time = False
                
    def increment_sequence(self):
        self.sequences.setdefault((self.odid, self.streamid), 0)
        self.sequences[(self.odid, self.streamid)] += 1
        
    def scan_setlist(self):
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
        
        This populates message header fields and the internal setlist,
        and should be called for each new message before iterating
        over records.
       
        Arguments:
        stream -- a stream object. read(length) on this object must return
                  a bytes or byte iterator, and will be called twice per 
                  message, once for the header and once for the body.
     
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
                                   str(len(msgbody))+", expected"+
                                   (self.length - _msghdr_st.size)+")")
        self.mbuf[_msghdr_st.size:self.length] = msgbody
        
        # populate setlist
        self.scan_setlist()
            
    def from_bytes(self, bytes):
        """Read an IPFIX message from a byte array.
        
        This populates message header fields and the internal setlist.
        
        Arguments:
        bytes -- a byte array containing a complete IPFIX message.
        
        """
        # make a copy of the byte array
        self.mbuf[0:len(bytes)] = bytes

        # parse message header 
        if (len(bytes) < _msghdr_st.size):
            raise IpfixDecodeError("Message too short ("+str(len(msghdr)) +")")

        (version, self.length, self.sequence, self.export_epoch, self.odid) = _msghdr_st.unpack_from(self.mbuf, 0)
        
        # verify version and length
        if version != 10:
            raise IpfixDecodeError("Illegal or unsupported version " + 
                                   str(version))
        
        if self.length < 20:
            raise IpfixDecodeError("Illegal message length" + str(self.length))
        
        # populate setlist
        self.scan_setlist()
            
    def record_iterator(self, 
                        decode_fn=template.Template.decode_namedict_from, 
                        tmplaccept_fn=accept_all_templates, 
                        recinf = None):
        """Low-level interface to record iteration.
        
        Iterate over records in an IPFIX message previously read with 
        read_message() or from_bytes(). Automatically handles templates in
        set order. By default, iterates over each record in the stream as a
        dictionary mapping information element name to value.
        
        Keyword arguments:
        decode_fn -- Decode function, with signature f(template, buffer, 
                     offset, recinf) -> record. This is generally an instance
                     method of the Template class providing the type of record 
                     desired. Default is Template.decode_namedict_from.
        tmplaccept_fn -- Template acceptance function, with signature 
                         f(template) -> boolean. Passed a template after the
                         template is decoded, returns True if the caller wants
                         to receive records in data sets for that template.
                         Default is to accept every template.
        recinf -- Record information, opaquely passed to decode function; see
                  recinf on each decode function for more.

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
                        self.increment_sequence()
                except KeyError:
                    #FIXME provide set buffer for sets without templates
                    pass
            else:
                #FIXME disable sequence checking on skipped sets
                pass

    def namedict_iterator(self):
        return self.record_iterator(
                decode_fn = template.Template.decode_namedict_from)
    
    def iedict_iterator(self):
        return self.record_iterator(
                decode_fn = template.Template.decode_iedict_from)
    
    def tuple_iterator(self, ielist):
        tmplaccept_fn = lambda tmpl: \
                functools.reduce(operator.__and__, 
                                 (ie in tmpl.ies for ie in ielist))
        return self.record_iterator(
                decode_fn = template.Template.decode_tuple_from, 
                tmplaccept_fn = tmplaccept_fn, 
                recinf = ielist)          

    def to_bytes(self):
        # Close final set 
        self.export_close_set()
        
        # Get sequence number and export time if necessary
        self.sequences.setdefault((self.odid, self.streamid), 0) # FIXME why do we need this?
        self.sequence = self.sequences[(self.odid, self.streamid)]
        
        if self.auto_export_time:
            self.export_epoch = int(datetime.utcnow().timestamp())
        
        # Update message header in buffer
        _msghdr_st.pack_into(self.mbuf, 0, 10, self.length, 
                             self.sequence, self.export_epoch, self.odid)
    
        
        return self.mbuf[0:self.length].tobytes()

    def write_message(self, stream):
        stream.write(self.to_bytes())

    def add_template(self, tmpl, export=True):
        self.templates[(self.odid, tmpl.tid)] = tmpl
        if export:
            self.export_template(tmpl)
    
    def delete_template(self, tid, export=True):
        setid = self.templates[self.odid, tid].native_setid()
        del(self.templates[self.odid, tid])
        if export:
            self.export_template_withdrawal(setid, tid)
    
    def begin_export(self, odid = None):
        # set new domain if necessary
        if odid:
            self.odid = odid
        
        # reset message and zero header
        self.length = _msghdr_st.size
        self.cursetoff = self.length
        self.mbuf[0:_msghdr_st.size] = bytes([0] * _msghdr_st.size)
    
        if self._mtu <= self.length:
            raise IpfixEncodeError("MTU too small: "+str(self._mtu))
    
        # no current set
        self.cursetid = None
        
    def export_new_set(self, setid):
        # close current set if any
        self.export_close_set()

        if setid >= 256:
            # make sure we have a template for the set
            if not ((self.odid, setid) in self.templates):
                raise IpfixEncodeError("can't start set without template id " + 
                                       str(setid))

            # make sure we have room to export at least one record
            tmpl = self.templates[(self.odid, setid)]
            if self.length + _sethdr_st.size + tmpl.minlength > self._mtu:
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
        
    def export_close_set(self):
        if self.cursetid:
            _sethdr_st.pack_into(self.mbuf, self.cursetoff, 
                                 self.cursetid, self.length - self.cursetoff)
            self.cursetid = None
        
    def export_ensure_set(self, setid):
        if self.cursetid != setid:
            self.export_new_set(setid)

    def export_needs_flush(self):
        if not self.cursetid and self.length <= _msghdr_st.size:
            return False
        else:
            return True
        
    def export_template(self, tmpl):
        self.export_ensure_set(tmpl.native_setid())
        
        if self.length + tmpl.enclength > self._mtu:
            raise EndOfMessage
        
        self.length = tmpl.encode_template_to(self.mbuf, self.length, 
                                              tmpl.native_setid())

    def export_template_withdrawal(self, setid, tid):
        self.export_ensure_set(setid)
        
        if self.length + template.withdrawal_length(setid) > self._mtu:
            raise EndOfMessage
        
        self.length = template.encode_withdrawal_to(self.mbuf, self.length, 
                                                    setid, tid)
        
    def export_record(self, rec, 
                      encode_fn=template.Template.encode_namedict_to, 
                      recinf = None):
        savelength = self.length
        
        try:
            self.length = encode_fn(self.curtmpl, self.mbuf, self.length, rec, recinf)
        except struct.error: # out of bounds on the underlying mbuf 
            self.length = savelength
            raise EndOfMessage()
        
        # check for mtu overrun
        if self.length > self._mtu:
            self.length = savelength
            raise EndOfMessage()

        self.increment_sequence()

    def export_namedict(self, rec):
        self.export_record(rec, template.Template.encode_namedict_to)
    
    def export_iedict(self, rec):
        self.export_record(rec, template.Template.encode_iedict_to)
        
    def export_tuple(self, rec, ielist = None):
        self.export_record(rec, template.Template.encode_tuple_to, ielist)