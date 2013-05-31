import xml.etree.ElementTree as etree
import urllib.request as urlreq
from warnings import warn

from . import types

def iana_xml_to_iespec(uri = "http://www.iana.org/assignments/ipfix/ipfix.xml"):
    iespecs = []

    nsmap = { "iana" : "http://www.iana.org/assignments" }

    res = urlreq.urlopen(uri)    
    root = etree.parse(res).getroot()
    
    for recelem in root.findall("iana:registry[@id='ipfix-information-elements']/iana:record", nsmap):
        name = recelem.find("iana:name", nsmap)
        num = recelem.find("iana:elementId", nsmap)
        ietype = recelem.find("iana:dataType", nsmap)
        
        if not name or not num or not ietype:
            continue
        
        ietype = types.for_name(ietype.text)
        
        if not ietype:
            continue
                
        iespecs.append("%s(%u)<%s>[%u]" % (name.text, int(num.text), ietype.name, ietype.size))
    
    return iespecs