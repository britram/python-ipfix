from . import message

class MessageStreamWriter:
    def __init__(self, stream, mtu=65535):
        self.stream = stream
        self.msg = message.MessageBuffer()    
        self.msg.mtu = mtu
        self.msgcount = 0
        
    def retry_after_flush(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except message.EndOfMessage:
            self.flush()
            return fn(*args, **kwargs)
    
    def set_domain(self, odid):
        if self.msg.export_needs_flush:
            self.msg.write_message(self.stream)
        self.msg.begin_export(odid)

    def add_template(self, tmpl):
        self.msg.add_template(tmpl)
    
    def set_export_template(self, tid):
        self.curtid = tid
        self.retry_after_flush(message.MessageBuffer.export_ensure_set, 
                               self.msg, self.curtid)
        
    def export_namedict(self, rec):
        self.retry_after_flush(message.MessageBuffer.export_ensure_set, 
                               self.msg, self.curtid)
        self.retry_after_flush(message.MessageBuffer.export_namedict, 
                               self.msg, rec)
            
    def export_tuple(self, rec, ielist = None):
        self.retry_after_flush(message.MessageBuffer.export_ensure_set, 
                               self.msg, self.curtid)
        self.retry_after_flush(message.MessageBuffer.export_tuple, 
                               self.msg, rec, ielist)
    
    def flush(self, final=False):
        setid = self.msg.cursetid
        self.msg.write_message(self.stream)
        self.msgcount += 1
        if not final:
            self.msg.begin_export()
            self.msg.export_ensure_set(setid)

def to_stream(stream):
    return MessageStreamWriter(stream)          