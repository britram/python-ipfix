from warnings import warn 
from . import template

# Builtin exception
class IPFIXDecodeError(Exception):
    def __init__(self, *args):
        super().__init__(args)

from struct import Struct

_sethdr_st = Struct("!HH")
_msghdr_st = Struct("!HHLLL")

class MessageStreamReader:
    """docstring for MessageStreamReader"""
    def __init__(self, stream):
        self.stream = stream
        self.mbuf = bytearray(65536)
        self.length = 0
        self.sequence = None
        self.export_time = None
        self.odid = None
        self.setlist = []
        self.templates = {}
        self.msgcount = 0
        self.tmplcount = 0
        self.reccount = 0
    
    def deframe(self):
        """deframe message and find set offsets"""
        # Start at the beginning
        offset = 0
        self.setlist.clear()
        
        # deframe and parse message header 
        msghdr = self.stream.read(_msghdr_st.size)
        if (len(msghdr) == 0):
            raise EOFError()
        elif (len(msghdr) < _msghdr_st.size):
            raise IPFIXDecodeError("Short read in message header ("+ str(len(msghdr)) +" octets")

        self.mbuf[0:_msghdr_st.size] = msghdr
        (version, self.length, self.sequence, self.export_time, self.odid) = _msghdr_st.unpack_from(self.mbuf, offset)
        offset += _msghdr_st.size
        
        # verify version and length
        if version != 10:
            raise IPFIXDecodeError("Illegal or unsupported version " + str(version))
        
        if self.length < 20:
            raise IPFIXDecodeError("Illegal message length" + str(self.length))
            
        # read the rest of the message into the buffer
        msgbody = self.stream.read(self.length-offset)
        if len(msgbody) < self.length - offset:
            raise IPFIXDecodeError("Short read in message body (got "+str(len(msgbody))+", expected"+(self.length - offset)+")")
        self.mbuf[offset:self.length-offset] = msgbody
        
        # iterate over message and built setlist
        while (offset < self.length):
            (setid, setlen) = _sethdr_st.unpack_from(self.mbuf, offset)
            if offset + setlen > self.length:
                raise IPFIXDecodeError("Set too long for message")
            self.setlist.append((offset, setid, setlen))
            offset += setlen

        self.msgcount += 1

    def dict_iterator(self):
        """return an iterator over records in messages in the stream""" 
        try:
            while(True):
                self.deframe()
                for (offset, setid, setlen) in self.setlist:
                    setend = offset + setlen
                    offset += _sethdr_st.size # skip set header in decode
                    if setid == 2:
                        while offset < setend:
                            (tmpl, offset) = template.decode_from_buffer(setid, self.mbuf, offset)
                            self.templates[(self.odid, tmpl.tid)] = tmpl
                            self.tmplcount += 1
                            print ("read template "+repr((self.odid, tmpl.tid))+": "+str(tmpl.count())+" IEs, minlen "+str(tmpl.minlength))
                    elif setid == 3:
                        self.tmplcount += 1
                        warn("skipping Options Template")
                    elif setid < 256:
                        warn("skipping illegal set id "+setid)
                    else:
                        try:
                            tmpl = self.templates[(self.odid), setid]
                            while offset + tmpl.minlength <= setend:
                                (rec, offset) = tmpl.decode_dict_from(self.mbuf, offset)
                                yield rec
                                self.reccount += 1
                        except KeyError:
                            warn("missing template for domain "+str(self.odid)+" set id "+str(setid))
                            
        except EOFError:
            return

def from_stream(stream):
    return MessageStreamReader(stream)          