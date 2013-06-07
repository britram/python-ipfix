from warnings import warn 
from functools import reduce
import operator
from . import template



from struct import Struct

_sethdr_st = Struct("!HH")
_msghdr_st = Struct("!HHLLL")

def _accept_all_templates(tmpl):
    return True

class MessageStreamReader:
    """docstring for MessageStreamReader"""
    def __init__(self, stream):
        self.stream = stream
        self.mbuf = memoryview(bytearray(65536))
        self.length = 0
        self.sequence = None
        self.export_time = None
        self.odid = None
        self.setlist = []
        self.templates = {}
        self.msgcount = 0
        self.tmplcount = 0
        self.reccount = 0
        self.notmplcount = 0
        self.setskipcount = 0
    
    def deframe_ipfix(self):
        """deframe message and find set offsets"""
        # Start at the beginning
        offset = 0
        self.setlist.clear()
        
        # deframe and parse message header 
        msghdr = self.stream.read(_msghdr_st.size)
        if (len(msghdr) == 0):
            raise EOFError()
        elif (len(msghdr) < _msghdr_st.size):
            raise IpfixDecodeException("Short read in message header ("+ str(len(msghdr)) +" octets")

        self.mbuf[0:_msghdr_st.size] = msghdr
        (version, self.length, self.sequence, self.export_time, self.odid) = _msghdr_st.unpack_from(self.mbuf, offset)
        offset += _msghdr_st.size
        
        # verify version and length
        if version != 10:
            raise IpfixDecodeException("Illegal or unsupported version " + str(version))
        
        if self.length < 20:
            raise IpfixDecodeException("Illegal message length" + str(self.length))
            
        # read the rest of the message into the buffer
        msgbody = self.stream.read(self.length-offset)
        if len(msgbody) < self.length - offset:
            raise IPFIXDecodeError("Short read in message body (got "+str(len(msgbody))+", expected"+(self.length - offset)+")")
        self.mbuf[offset:self.length] = msgbody
        
        # iterate over message and built setlist
        while (offset < self.length):
            (setid, setlen) = _sethdr_st.unpack_from(self.mbuf, offset)
            if offset + setlen > self.length:
                raise IPFIXDecodeError("Set too long for message")
            self.setlist.append((offset, setid, setlen))
            offset += setlen

        self.msgcount += 1

    # FIXME needs a method to pass in a "i want records from this template" function to be applied to all new templates.
    def record_iterator(self, decode_fn = template.Template.decode_namedict_from, tmplaccept_fn = _accept_all_templates, recinf = None):
        """return an iterator over records in messages in the stream
           using a function (template, buffer, offset) => (record, offset) 
           to decode records"""
           
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
                                print ("accepted template "+repr((self.odid, tmpl.tid))+": "+str(tmpl.count())+" IEs, minlen "+str(tmpl.minlength))
                                accepted_setid.add((self.odid, tmpl.tid))
                            else:
                                print ("rejected template "+repr((self.odid, tmpl.tid))+": "+str(tmpl.count())+" IEs, minlen "+str(tmpl.minlength))
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
                            #FIXME neet set buffer for sets without templates
                            self.notmplcount += 1
                    else:
                        self.setskipcount += 1
                            
        except EOFError:
            return
            
    def namedict_iterator(self):
        return self.record_iterator(decode_fn = template.Template.decode_namedict_from)
    
    def iedict_iterator(self):
        return self.record_iterator(decode_fn = template.Template.decode_iedict_from)
    
    def tuple_iterator(self, ielist):
        tmplaccept_fn = lambda tmpl: reduce(operator.__and__, (ie in tmpl.ies for ie in ielist))
        return self.record_iterator(decode_fn = template.Template.decode_tuple_from, tmplaccept_fn = tmplaccept_fn, recinf = ielist)
        
def from_stream(stream):
    return MessageStreamReader(stream)          