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
