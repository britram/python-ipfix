#!/usr/bin/env python3

import ipfix.reader
import ipfix.ie
import pprint

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()
ipfix.ie.load_specfile("../qof/test/qof.iespec")

r = ipfix.reader.from_stream(open("../qof/yaf-headers.ipfix", mode="rb"))

pp = pprint.PrettyPrinter(indent = 2)

for rec in r.dict_iterator():
    pp.pprint(rec)
