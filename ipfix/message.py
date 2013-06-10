from . import template

import operator
import functools
import datetime
from struct import Struct

_sethdr_st = Struct("!HH")
_msghdr_st = Struct("!HHLLL")

def _accept_all_templates(tmpl):
    return True    

class MessageBuffer:
    def __init__(self):
        self.mbuf = memoryview(bytearray(65536))

        self.length = 0
        self.sequence = None
        self.export_epoch = None
        self.odid = None
        self.stream = 0

        self.templates = {}
        self.sequences = {}
        
        self.setlist = []

        self.cursetoff = 0
        self.cursetid = 0
        self.mtu = 65535
        
    def scan_setlist():
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
            raise IpfixDecodeException("Short read in message header ("+ 
                                       str(len(msghdr)) +")")

        self.mbuf[0:_msghdr_st.size] = msghdr
        (version, self.length, self.sequence, self.export_epoch, self.odid) = _msghdr_st.unpack_from(self.mbuf, 0)
        
        # verify version and length
        if version != 10:
            raise IpfixDecodeException("Illegal or unsupported version " + 
                                       str(version))
        
        if self.length < 20:
            raise IpfixDecodeException("Illegal message length" + 
                                       str(self.length))
            
        # read the rest of the message into the buffer
        msgbody = self.stream.read(self.length-_msghdr_st.size)
        if len(msgbody) < self.length - _msghdr_st.size:
            raise IPFIXDecodeError("Short read in message body (got "+
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
        elif (len(bytes) < _msghdr_st.size):
            raise IpfixDecodeException("Message too short ("+ 
                                       str(len(msghdr)) +")")

        (version, self.length, self.sequence, self.export_epoch, self.odid) = _msghdr_st.unpack_from(self.mbuf, 0)
        
        # verify version and length
        if version != 10:
            raise IpfixDecodeException("Illegal or unsupported version " + 
                                       str(version))
        
        if self.length < 20:
            raise IpfixDecodeException("Illegal message length" + 
                                       str(self.length))
        
        # populate setlist
        self.scan_setlist()
            
    def record_iterator(self, 
                        decode_fn=template.Template.decode_namedict_from, 
                        tmplaccept_fn=_accept_all_templates, 
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
        accepted_setid = set()
        
        try:
            while(True):
                self.deframe_ipfix()
                for (offset, setid, setlen) in self.setlist:
                    setend = offset + setlen
                    offset += _sethdr_st.size # skip set header in decode
                    if setid == 2 or setid == 3:
                        while offset < setend:
                            (tmpl, offset) = template.decode_template_from(setid, self.mbuf, offset)
                            self.templates[(self.odid, tmpl.tid)] = tmpl
                            self.tmplcount += 1
                            if tmplaccept_fn(tmpl):
                                print ("accepted template "+
                                       repr((self.odid, tmpl.tid))+": "+
                                       str(tmpl.count())+" IEs, minlen "+
                                       str(tmpl.minlength))
                                accepted_setid.add((self.odid, tmpl.tid))
                            else:
                                print ("rejected template "+
                                       repr((self.odid, tmpl.tid))+": "+
                                       str(tmpl.count())+" IEs, minlen "+
                                       str(tmpl.minlength))
                                accepted_setid.discard((self.odid, tmpl.tid))
                            
                    elif setid < 256:
                        warn("skipping illegal set id "+setid)
                    elif (self.odid, setid) in accepted_setid:
                        try:
                            tmpl = self.templates[(self.odid, setid)]
                            while offset + tmpl.minlength <= setend:
                                (rec, offset) = decode_fn(tmpl, self.mbuf, offset, recinf = recinf)
                                yield rec
                                self.reccount += 1
                        except KeyError:
                            #FIXME need set buffer for sets without templates
                            self.notmplcount += 1
                    else:
                        self.setskipcount += 1
                            
        except EOFError:
            return

    def get_export_time(self):
        return datetime.utcfromtimestamp(self.export_epoch)

    def to_bytes(self):    
        # Write message header into buffer
        _msghdr_st.pack_into(self.mbuf, 0, 10, self.length, 
                             self.sequence, self.export_epoch, self.odid)
    
        # Return bytes
        return self.mbuf[0:self.length].tobytes()

    def write_message(self, stream):
        stream.write(self.to_bytes())

    def set_export_time(self, dt=datetime.utcnow()):
        self.export_epoch = int(dt.timestamp))
        
    def add_template(self, tmpl, append=False):
        self.templates[(self.odid, tmpl.tid)] = template
        if append:
            self.append_template(tmpl)
    
    def close_set(self):
        pass
    
    def append_template(self, tmpl):
        pass
            
    def append_record(self, rec, 
                      encode_fn=template.Template.encode_namedict_to, 
                      recinf = None):
        pass
        