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
Provides the PduBuffer class for decoding NetFlow V9 Protocol Data 
Units (PDUs). 

This module is not yet complete.

"""

from . import template
from .template import IpfixEncodeError, IpfixDecodeError
from .message import accept_all_templates

import operator
import functools
import struct
from datetime import datetime
from datetime import timezone
from warnings import warn

NETFLOW9_VERSION = 9

_sethdr_st = struct.Struct("!HH")
_pduhdr_st = struct.Struct("!HHLLLL")

class PduBuffer:
    """
    Implements a buffer for reading NetFlow V9 PDUs from a stream or packet.
    
    This class is not yet complete.
    
    """
    def __init__(self):
        """Create a new PduBuffer instance."""
        self.mbuf = memoryview(bytearray(65536))

        self.length = 0
        self.cur = 0
        
        self.reccount = None
        self.sequence = None
        self.export_epoch = None
        self.base_epoch = None
        self.sysuptime_ms = None
        self.odid = 0

        self.templates = {}
        self.accepted_tids = set()
        self.sequences = {}
        
        self.last_tuple_iterator_ielist = None
        
    def __repr__(self):
        return "<PDUBuffer domain "+str(self.odid)+\
               " length "+str(self.length)+addinf+">"

    def _increment_sequence(self, inc = 1):
        self.sequences.setdefault((self.odid, self.streamid), 0)
        self.sequences[(self.odid, self.streamid)] += inc

    def parse_pdu_header(self):
        (version, self.reccount, self.sysuptime_ms, 
             self.export_epoch, self.sequence, self.odid) = \
             _pduhdr_st.unpack_from(self.mbuf, 0)
        
        if version != NETFLOW9_VERSION:
            raise IpfixDecodeError("Illegal or unsupported version " + 
                                   str(version))
        
        self._increment_sequence(self.reccount)
        self.basetime_epoch = self.export_epoch - (self.sysuptime_ms / 1000)
    
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
        while True:
            try:
                (offset, setid, setlen) = self.next_set()
            except EOFError:
                break
                
            setend = offset + setlen
            offset += _sethdr_st.size # skip set header in decode
            if setid == template.V9_TEMPLATE_SET_ID or \
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

    def active_template_ids(self):
        """
        Get an iterator over all active template IDs in the current domain.
        Provided to allow callers to export some or all active Templates across
        multiple Messages.
        
        :returns: a template ID iterator
        
        """
        for tk in filter(lambda k: k[0] == self.odid, self.templates):
            yield tk[1]  
    
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

class StreamPduBuffer(PduBuffer):
    def __init__(self, stream):
        super().__init__()
        
        self.stream = stream
    
    def next_set(self):
        """
        Reads the next set from the stream. Automatically reads PDU headers, as
        well, since PDU headers are treated as a special case of set header in
        streamed PDU reading.
    
        Raises EOF to signal end of stream.
    
        Yes, NetFlow V9 really is that broken as a storage format,
        and this is the only way to stream it without counting records 
        (which we can't do in the tuple-reading case).
    
        """
        self.mbuf[0:_sethdr_st.size]= self.stream.read(_sethdr_st.size)
        (setid, setlen) = _sethdr_st.unpack_from(self.mbuf)
    
        while setid == NETFLOW9_VERSION:
            # Actually, this is the first part of a message header.
            # Grab the rest from the stream, then parse it.
            self.mbuf[_sethdr_st.size:_pduhdr_st.size] = \
                self.stream.read(_pduhdr_st.size - _sethdr_st.size)
            parse_pdu_header()
            # Now try again to get a set header
            self.mbuf[0:_sethdr_st.size]= self.stream.read(_sethdr_st.size)
            (setid, setlen) = _sethdr_st.unpack_from(self.mbuf)
    
        # read the set body into the buffer
        self.mbuf[_sethdr_st.size:setlen] = \
            self.stream.read(setlen, _sethdr_st.size)
    
        # return pointers for record_iterator
        return (0, setid, setlen)
