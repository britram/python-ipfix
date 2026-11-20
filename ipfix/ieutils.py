#
# python-ipfix (c) 2013-2026 Brian Trammell.
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
Utilities for generating IESpec files from the IANA IPFIX Information Elements
registry (CSV or XML) and deriving RFC 5103 reverse Information Elements.
"""

import csv
import io
import urllib.request as urlreq
import xml.etree.ElementTree as etree

from . import ie, types

IANA_CSV_URI = "https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv"
IANA_XML_URI = "https://www.iana.org/assignments/ipfix/ipfix.xml"

# RFC 5103 §6.1: Information Elements that are not reversible (flow-key directional
# identifiers, scope identifiers, etc.)
_NON_REVERSIBLE_SUBSTRINGS = ("Source", "Destination", "source", "destination")
_NON_REVERSIBLE_NAMES = frozenset({"messageScope"})


def is_reversible_ie(name):
    """Return True if an IANA IE name is eligible for an RFC 5103 reverse counterpart."""
    if name in _NON_REVERSIBLE_NAMES:
        return False
    return not any(tok in name for tok in _NON_REVERSIBLE_SUBSTRINGS)


def parse_iana_csv(csv_file):
    """Parse an open text file/stream of the IANA IPFIX IE CSV into IESpec strings."""
    iespecs = []
    reader = csv.DictReader(csv_file)
    for row in reader:
        name = (row.get("Name") or "").strip()
        typename = (row.get("Abstract Data Type") or "").strip()
        num = (row.get("ElementID") or "").strip()
        if not (name and typename and num.isdigit()):
            continue
        try:
            ietype = types.for_name(typename)
        except types.IpfixTypeError:
            # Skip types not yet implemented (e.g. RFC 6313 structured data)
            continue
        iespecs.append(f"{name}({int(num)})<{ietype.name}>[{ietype.length}]")
    return iespecs


def iana_csv_to_iespec(uri=IANA_CSV_URI):
    """Fetch the IANA IPFIX IE CSV over HTTPS and return a list of IESpec strings."""
    with urlreq.urlopen(uri) as res:
        text = io.TextIOWrapper(res, encoding="utf-8")
        return parse_iana_csv(text)


def parse_iana_xml(xml_file):
    """Parse an open binary/text file of the IANA IPFIX XML into IESpec strings."""
    iespecs = []
    nsmap = {"iana": "http://www.iana.org/assignments"}
    root = etree.parse(xml_file).getroot()

    for recelem in root.iterfind(
        "iana:registry[@id='ipfix-information-elements']/iana:record", nsmap
    ):
        name = typename = num = None
        for fieldelem in recelem.iter():
            if fieldelem.tag.endswith("name"):
                name = fieldelem.text
            elif fieldelem.tag.endswith("dataType"):
                typename = fieldelem.text
            elif fieldelem.tag.endswith("elementId"):
                num = fieldelem.text

        if name and typename and num and num.isdigit():
            try:
                ietype = types.for_name(typename)
            except types.IpfixTypeError:
                continue
            iespecs.append(f"{name}({int(num)})<{ietype.name}>[{ietype.length}]")

    return iespecs


def iana_xml_to_iespec(uri=IANA_XML_URI):
    """Fetch the IANA IPFIX XML over HTTPS and return a list of IESpec strings."""
    with urlreq.urlopen(uri) as res:
        return parse_iana_xml(res)


def reverse_iespec(iespec):
    """Generate the RFC 5103 reverse counterpart IESpec for a given IESpec."""
    name, pen, num, typename, length = ie.parse_spec(iespec)
    revname = "reverse" + name[0].upper() + name[1:]
    if pen:
        num |= 0x4000
    else:
        pen = 29305

    return f"{revname}({pen}/{num})<{typename}>[{length}]"


def write_specfile(filename, iespecs):
    """Write a sequence of IESpec strings to a file, one per line."""
    with open(filename, "w", encoding="utf-8") as f:
        for spec in iespecs:
            f.write(spec)
            f.write("\n")
