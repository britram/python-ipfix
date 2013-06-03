import xml.etree.ElementTree as etree
import urllib.request as urlreq
from warnings import warn

from . import types
from . import ie

def iana_xml_to_iespec(uri = "http://www.iana.org/assignments/ipfix/ipfix.xml"):
    iespecs = []

    nsmap = { "iana" : "http://www.iana.org/assignments" }

    res = urlreq.urlopen(uri)    
    root = etree.parse(res).getroot()
    
    for recelem in root.iterfind("iana:registry[@id='ipfix-information-elements']/iana:record", nsmap):
        (name, typename, num) = (None, None, None)
        for fieldelem in recelem.iter():
            if fieldelem.tag[-4:] == "name":
                name = fieldelem.text
            elif fieldelem.tag[-8:] == "dataType":
                typename = fieldelem.text
            elif fieldelem.tag[-9:] == "elementId":
                num = fieldelem.text


        if name and typename and num:
            ietype = types.for_name(typename)
            if ietype:
                iespecs.append("%s(%u)<%s>[%u]" % (name, int(num), ietype.name, ietype.length()))            
        
    return iespecs


def reverse_iespec(iespec):
    (name, pen, num, typename, length) = ie.parse_spec(iespec)
    revname = "reverse" + name[0].capitalize() + name[1:]
    if pen:
        num |= 0x4000
    else:
        pen = 29305

    return "%s(%u/%u)<%s>[%u]" % (revname, pen, num, typename, length)    


def write_specfile(filename, iespecs):
    with open(filename, "w") as f:
        for spec in iespecs:
            f.write(spec)
            f.write("\n")
