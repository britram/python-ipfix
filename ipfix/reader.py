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
    
    def deframe(self):
        """deframe message and find set offsets"""
        # Start at the beginning
        offset = 0
        self.setlist.clear()
        
        # deframe and parse message header 
        self.mbuf[0:_msghdr_st.size] = self.stream.read(_msghdr_st.size)
        (version, self.length, self.sequence, self.export_time, self.odid) = _msghdr_st.unpack_from(self.mbuf, offset)
        offset += _msghdr_st.size
        
        # verify version and length
        if version != 10:
            raise IPFIXDecodeError("Illegal or unsupported version " + str(version))
        
        if self.length < 20:
            raise IPFIXDecodeError("Illegal message length" + str(self.length))
            
        # read the rest of the message into the buffer
        self.mbuf[offset:self.length-offset] = self.stream.read(self.length-offset)
        
        # iterate over message and built setlist
        while (offset < self.length):
            (setid, setlen) = _sethdr_st.unpack_from(self.mbuf, offset)
            if offset + setlen > self.length:
                raise IPFIXDecodeError("Set too long for message")
            self.setlist.append((offset, setid, setlen))
            offset += setlen

    def dict_iterator(self):
        """return an iterator over records in messages in the stream""" 
        try:
            while(True):
                self.deframe()
                # FIXME check 
                for (offset, setid, setlen) in self.setlist:
                    setend = offset + setlen
                    if setid == 2:
                        while offset < setend:
                            (tmpl, offset) = template.decode_from_buffer(setid, self.mbuf, offset)
                            self.templates[(self.odid, tmpl.tid)] = tmpl
                            print ("read template "+repr((self.odid, tmpl.tid))+": "+str(tmpl.count())+" IEs, minlen "+str(tmpl.minlength))
                    elif setid == 3:
                        warn("skipping Options Template")
                    elif setid < 256:
                        warn("skipping illegal set id "+setid)
                    else:
                        try:
                            tmpl = self.templates[(self.odid), setid]
                            while offset + tmpl.minlength <= setend:
                                (rec, offset) = tmpl.decode_dict_from(self.mbuf, offset)
                                yield rec
                        except KeyError:
                            warn("missing template for domain "+str(self.odid)+" set id "+str(setid))
                            
        except EOFError:
            return

def from_stream(stream):
    return MessageStreamReader(stream)          