import re
import os.path
from . import types
from functools import total_ordering, reduce
import operator

_iespec_re = re.compile('^([^\s\[\<\(]+)?(\(((\d+)\/)?(\d+)\))?(\<(\S+)\>)?(\[(\S+)\])?')

# Internal information element registry
_ieForName = {}
_ieForNum = {}

def _register_ie(ie):
    _ieForName[ie.name] = ie
    _ieForNum[(ie.pen, ie.num)] = ie
    
    return ie
    
@total_ordering
class InformationElement:
    """An IPFIX Information Element (IE) has a name, element number (num), 
       a private enterprise number (pen; 0 if it is an IANA registered IE,
       a type, and a length"""
    def __init__(self, name, pen, num, ietype, length):
        
        if name:
            self.name = name
        else: 
            self.name = "_ipfix_%u_%u" % (pen, num)

        if length:
            self.length = length
        else:
            self.length = ietype.length

        self.pen = pen
        self.num = num
        self.type = ietype.for_length(self.length)

    def __eq__(self, other):
        return ((self.pen, self.num) == (other.pen, other.num))
    
    def __lt__(self, other):
        return ((self.pen, self.num) < (other.pen, other.num))

    def __repr__(self):
        return "InformationElement(%s, %s, %s, %s, %s)" % (repr(self.name), 
               repr(self.pen), repr(self.num), repr(self.type), 
               repr(self.length))

    def __str__(self):
        return "%s(%u/%u)%s[%u]" % (self.name, self.pen, self.num, str(self.type), self.length)
    
    def __hash__(self):
        return (self.num << 16) ^ self.pen
    
    def for_length(self, length):
        if not length or length == self.length:
            return self
        else:
            return self.__class__(self.name, self.pen, self.num, self.type, length)

@total_ordering
class InformationElementList:
    def __init__(self, iterable = None):
        self.inner = []
        
        if iterable:
            for x in iterable:
                self.append(x)

    def __iter__(self):
        return iter(self.inner)

    def __eq__(self, other):
        return self.inner == other.inner
        
    def __lt__(self, other):
        return self.inner < other.inner
    
    def __repr__(self):
        return "InformationElementList(" + ",".join((repr(x) for x in self.inner)) + ")"

    def __str__(self):
        return "\n".join((str(x) for x in self.inner))
    
    def __hash__(self):
        if not self.hashcache:
            self.hashcache = reduce(operator.xor, (hash(x) for x in self.inner))

        return self.hashcache

    def __len__(self):
        return len(self.inner)
    
    def __getitem__(self, key):
        return self.inner[key]
    
    def index(self, x):
        return self.inner.index(x)

    def append(self, ie):
        self.inner.append(ie)
        self.hashcache = None

def parse_spec(spec):
    """Parse an iespec into name, pen, number, typename, and length fields"""
    (name, pen, num, typename, length) = _iespec_re.match(spec).group(1,4,5,7,9)
    
    if pen: 
        pen = int(pen)
    else:
        pen = 0
    
    if num:
        num = int(num)
    else:
        num = 0
    
    if length:
        length = int(length)
    else:
        length = 0
        
    if not typename:
        typename = False
    
    return (name, pen, num, typename, length)
    
def list(iterable = None):
    return InformationElementList(iterable)

def for_spec(spec):
    (name, pen, num, typename, length) = parse_spec(spec)

    if not name and not pen and not num and not typename and not length:
        raise ValueError("unrecognized IE spec "+spec)
    
    if name and not pen and not num and name in _ieForName:
            # lookup in name registry
            return _ieForName[name].for_length(length)
    
    if num and (pen, num) in _ieForNum:
            # lookup in number registry
            return _ieForNum[(pen, num)].for_length(length)
    
    # try to create new registered IE
    if not typename:
        raise ValueError("Cannot create new IE without valid type")
    
    ietype = types.for_name(typename)
    
    if not ietype:
        raise ValueError("unrecognized type name '"+typename+"'")
    
    return _register_ie(InformationElement(name, pen, num, ietype, length))
 
def for_template_entry(pen, num, length):
    if ((pen, num) in _ieForNum):
        return _ieForNum[(pen, num)].for_length(length)
    
    return _register_ie(InformationElement(None, pen, num, types.for_name("octetArray"), length))

def load_specfile(filename):
    with open(filename) as f:
        for line in f:
            for_spec(line)

def clear_infomodel():
    _ieForName.clear()
    _ieForNum.clear()

def use_iana_default():
    load_specfile(os.path.join(os.path.dirname(__file__), "iana.iespec"))
    
def use_5103_default():
    load_specfile(os.path.join(os.path.dirname(__file__), "rfc5103.iespec"))
    