#!/usr/bin/env python3

import ipfix.reader
import ipfix.ie

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()

r = ipfix.reader.from_stream(open("../qof/yaf-headers.ipfix", mode="rb"))

for rec in r.dict_iterator():
    print(rec)
