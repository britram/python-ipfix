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
Interface to read IPFIX Messages from a stream. 

"""

from . import message

class MessageStreamReader:
    """
    Reads records from a stream of IPFIX messages. 
    
    Uses an :class:`ipfix.message.MessageBuffer` internally, and continually reads
    messages from the given stream into the buffer, iterating over records,
    until the end of the stream. Use :func:`from_stream` to get an instance.
    
    Suitable for reading from IPFIX files (see :rfc:`5655`) as well as from
    UDP or TCP sockets with :class:`socketserver.StreamRequestHandler`. 
    When opening a stream from a file, use mode='rb'.
    
    """
    def __init__(self, stream):
        self.stream = stream
        self.msg = message.MessageBuffer()    
        self.msgcount = 0
        
    def records_as_dict(self):
        """
        Iterate over all records in the stream, as dicts mapping IE names
        to values.
        
        :returns: a name dictionary iterator
        
        """
        try:
            while(True):
                self.msg.read_message(self.stream)
                yield from self.msg.namedict_iterator()
                self.msgcount += 1        
        except EOFError:
            return
            
    def records_as_tuple(self, ielist):
        """
        Iterate over all records in the stream containing all the IEs in 
        the given ielist. Records are returned as tuples in ielist order.
        
        :param ielist: an instance of :class:`ipfix.ie.InformationElementList`
                       listing IEs to return as a tuple
        :returns: a tuple iterator for tuples in ielist order
        """
        try:
            while(True):
                self.msg.read_message(self.stream)
                yield from self.msg.tuple_iterator(ielist)           
                self.msgcount += 1        
        except EOFError:
            return
        
def from_stream(stream):
    """
    Get a MessageStreamReader for a given stream
    
    :param stream: stream to read
    :return: a :class:`MessageStreamReader` wrapped around the stream.

    """
    return MessageStreamReader(stream)          