from . import message

class MessageStreamWriter:
    """
    Writes records to a stream of IPFIX messages.
    
    Uses an :class:`ipfix.message.MessageBuffer` internally, and continually
    writes records into messages, exporting messages to the stream each time the 
    maximum message size (MTU) is reached. Use :func:`to_stream` to get an
    instance.
    
    Suitable for writing to IPFIX files (see :rfc:`5655`) as well as to TCP 
    sockets. When writing a stream to a file, use mode='wb'.
    
    ..warning: This class is not yet suitable for UDP export; this is an open
               issue to be fixed in a subsequent release.
    
    """
    def __init__(self, stream, mtu=65535):
        self.stream = stream
        self.msg = message.MessageBuffer()    
        self.msg.mtu = mtu
        self.msgcount = 0
        
    def _retry_after_flush(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except message.EndOfMessage:
            self.flush()
            return fn(*args, **kwargs)
    
    def set_domain(self, odid):
        """
        Sets the observation domain for subsequent messages sent with 
        this Writer.
        
        :param odid: Observation domain ID to use for export. Note that
                     templates are scoped to observation domain, so 
                     templates will need to be added after switching to a 
                     new observation domain ID.

        """
        if self.msg.export_needs_flush():
            self.msg.write_message(self.stream)
        self.msg.begin_export(odid)

    def add_template(self, tmpl):
        """
        Add a template to this Writer. Adding a template makes it 
        available for use for exporting records; see :meth:`set_export_template`. 
        
        :param tmpl: the template to add

        """
        self.msg.add_template(tmpl)
    
    def set_export_template(self, tid):
        """
        Set the template to be used for export by subsequent calls to
        :meth:`export_namedict` and :meth:`export_tuple`.

        :param tid: Template ID of the Template that will be used to encode 
                    records to the Writer. The corresponding Template must 
                    have already been added to the Writer, see 
                    :meth:`add_template`.
        """
        self.curtid = tid
        self._retry_after_flush(message.MessageBuffer.export_ensure_set, 
                               self.msg, self.curtid)
        
    def export_namedict(self, rec):
        """
        Export a record to the message, using the current template
        The record is a dictionary mapping IE names to values. The
        dictionary must contain a value for each IE in the template. Keys in the
        dictionary not in the template will be ignored.
        
        :param rec: the record to export, as a dictionary
        
        """
        self._retry_after_flush(message.MessageBuffer.export_ensure_set, 
                               self.msg, self.curtid)
        self._retry_after_flush(message.MessageBuffer.export_namedict, 
                               self.msg, rec)
            
    def export_tuple(self, rec, ielist = None):
        self._retry_after_flush(message.MessageBuffer.export_ensure_set, 
                                self.msg, self.curtid)
        self._retry_after_flush(message.MessageBuffer.export_tuple, 
                                self.msg, rec, ielist)
    
    def flush(self):
        """
        Export an in-progress Message immediately.
        
        Used internally to manage message boundaries, but
        can also be used to force immediate export (e.g. to reduce delay
        due to buffer dwell time), as well as to finish write operations on
        a Writer before closing the underlying stream.
        """
        
        setid = self.msg.cursetid
        self.msg.write_message(self.stream)
        self.msgcount += 1
        self.msg.begin_export()
        self.msg.export_ensure_set(setid)

def to_stream(stream, mtu=65535):
    """
    Get a MessageStreamWriter for a given stream
    
    :param stream: stream to write
    :param mtu: maximum message size in bytes; defaults to 65535,
                the largest possible ipfix message.
    :return: a :class:`MessageStreamWriter` wrapped around the stream.

    """
    return MessageStreamWriter(stream, mtu)          