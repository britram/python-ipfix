from warnings import warn 
from functools import reduce
import operator
from . import message

from struct import Struct

_sethdr_st = Struct("!HH")
_msghdr_st = Struct("!HHLLL")

class MessageStreamReader:
    """docstring for MessageStreamReader"""
    def __init__(self, stream):
        self.stream = stream
        self.msg = message.MessageBuffer()    
        self.msgcount = 0
        
    def namedict_iterator(self):
        try:
            while(True):
                self.msg.read_message(self.stream)
                yield from self.msg.namedict_iterator()
                self.msgcount += 1        
        except EOFError:
            return
        
    def iedict_iterator(self):
        try:
            while(True):
                self.msg.read_message(self.stream)
                yield from self.msg.namedict_iterator()           
                self.msgcount += 1        
        except EOFError:
            return
    
    def tuple_iterator(self, ielist):
        try:
            while(True):
                self.msg.read_message(self.stream)
                yield from self.msg.tuple_iterator(ielist)           
                self.msgcount += 1        
        except EOFError:
            return
        
def from_stream(stream):
    return MessageStreamReader(stream)          