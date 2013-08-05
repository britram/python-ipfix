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
Provides the PDUBuffer class for decoding NetFlow V9 Protocol Data 
Units (PDUs). 

This module is not yet complete.

"""

_sethdr_st = struct.Struct("!HH")
_resthdr_st = struct.Struct("!LLLL")

class PDUBuffer:
    """
    Implements a buffer for reading NetFlow V9 PDUs from a stream or packet.
    
    This class is not yet complete.
    
    """
    def __init__(self):
        """Create a new MessageBuffer instance."""
        self.mbuf = memoryview(bytearray(65536))

        self.length = 0
        self.cur = 0
        
        self.sequence = None
        self.export_epoch = None
        self.base_epoch = None
        self.sysuptime_ms = None
        self.odid = 0

        self.templates = {}
        self.accepted_tids = set()
        self.sequences = {}
        
        self.setlist = []

        self.last_tuple_iterator_ielist = None
        
    def __repr__(self):
        return "<PDUBuffer domain "+str(self.odid)+\
               " length "+str(self.length)+addinf+">"
    
    def attach_stream(self, stream):
        pass

    def from_bytes(self, bytes):
        pass
    
    def next_pdu_header(self):
        pass
    
    #
    # The concept here: 
    #
    # either read an entire PDU at a time into the buffer with from_bytes
    # (if you have framing) or attach a stream, which will read the PDU
    # setwise into the buffer. In either case, at the _end_ of the decode, the
    # message is completely in the buffer.
    #
    # This means that the next set logic is kind of weird, because it has
    # to detect a new message (special Set ID 9), but only when reading from 
    # a stream, and when reading from a stream, it has to read the set into
    #
    # Consider refactoring this into stream_next_set and bytes_next_set,
    # or using inheritance -- there's no runtime reason to switch from one 
    # regime to the other.
    #
    
    def next_set(self):
        if self.stream:
            self.mbuf[self.cur:self.cur+_sethdr_st.size] = \
                               self.stream.read(_sethdr_st.size)
        
        (setid, setlen) = _sethdr_st.unpack_from(self.mbuf, self.cur)

        if setid == 9:
            if not self.stream:
                raise IpfixDecodeError("Illegal set ID in PDU")
            
            # not a set, really the beginning of a message header.
            # shift and read header
            
            # FIXME read and shift goes here
            
            next_pdu_header(self)
            
        else:
            # read the rest of the set into the buffer
            
            
    
    def record_iterator(self, 
                        decode_fn=template.Template.decode_namedict_from, 
                        tmplaccept_fn=accept_all_templates, 
                        recinf=None):
        """
        Low-level interface to record iteration.
        
        Iterate over records in a PDU; the buffer must either be attached to 
        a stream via :meth:`attach_stream` or have been preloaded with 
        :meth:`from_bytes`. Automatically handles 
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
        while (offset, setid, setlen) = next_set():
            setend = offset + setlen
            offset += _sethdr_st.size # skip set header in decode
            if setid == template.V9_TEMPLATE_SET_ID or\
               setid == template.V9_OPTIONS_SET_ID:
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
        Iterate over all records in the PDU containing all the IEs in 
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
        