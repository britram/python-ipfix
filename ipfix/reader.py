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
        self.domain_id = None
        self.setlist = []
        self.templates = {}
    
    """deframe message and find set offsets"""
    def deframe(self):
        # Start at the beginning
        offset = 0
        self.setlist.clear()
        
        # deframe and parse message header 
        self.mbuf[0:_msghdr_st.size] = self.stream.read(_msghdr_st.size)
        (version, self.length, self.sequence, self.export_time, self.domain_id) = _msghdr_st.unpack_from(self.mbuf, offset)
        offset += _msghdr_st.size
        
        # verify version and length
        if version != 10:
            raise IPFIXDecodeError("Illegal or unsupported version " + str(version))
        
        if self.length < 20:
            raise IPFIXDecodeError("Illegal message length" + str(self.length))
            
        # read the rest of the message into the buffer
        self.mbuf[offset:length-offset] = self.stream.read(length-offset)
        
        # iterate over message and built setlist
        while (offset < self.length):
            (setid, setlen) = _sethdr_st.unpack_from(self.mbuf, offset)
            if offset + setlen > self.length:
                raise IPFIXDecodeError("Set too long for message")
            self.setlist.append((offset, setid, setlen))
            offset += setlen

    """return an iterator over records in messages in the stream"""
    def dict_iterator(self):
        
        # FIXME make this work
        try:
            while(True):
                self.deframe()
                for (offset, setid, setlen) in setlist:
                    if setid == 2:
                        pass
                    elif setid == 3:
                        pass
                    elif setid < 256:
                        # FIXME warn on this instead
                        raise IPFIXDecodeError("illegal set ID")
                    else:
                        pass
        except EOFError:
            return
                    