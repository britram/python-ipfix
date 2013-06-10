#!/usr/bin/env python3

import ipfix.writer
import ipfix.template
import ipfix.ie
import argparse
import cProfile
import sys
import math

from datetime import datetime, timedelta

ap = argparse.ArgumentParser(description="Write a test pattern to an IPFIX file")
ap.add_argument('file', metavar='file', help='ipfix file to write')
args = ap.parse_args()

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()

# prof = cProfile.Profile()
# prof.enable()

w = ipfix.writer.to_stream(open(args.file, mode="wb"))

tuplespec = """observationTimeMilliseconds
               octetDeltaCount"""

tmpl = ipfix.template.from_iespec(1000,tuplespec.split())

basetime = datetime.utcnow() - timedelta(seconds=300000)

w.mtu = 1460
w.set_domain(1)
w.add_template(tmpl)
w.set_export_template(1000)

for i in range(100000):
    w.export_tuple((basetime + timedelta(seconds=i*30), int((math.sin(float(i)/100)+1)*100000)))

w.flush(True)

sys.stderr.write("wrote %u records to %u messages\n" %
                 (i, w.msgcount))
# prof.disable()
# prof.dump_stats("cprofile.out")