#!/usr/bin/env python3

import ipfix.reader
import ipfix.ie
import pprint
import argparse
import cProfile
import sys

ap = argparse.ArgumentParser(description="Dump an IPFIX file for debug purposes")
ap.add_argument('file', metavar='file', help='ipfix file to read')
ap.add_argument('--spec', metavar='specfile', help='iespec file to read')
args = ap.parse_args()

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()
if args.spec:
    ipfix.ie.load_specfile(args.spec)

# prof = cProfile.Profile()
# prof.enable()

r = ipfix.reader.from_stream(open(args.file, mode="rb"))

# tuplespec = """sourceIPv4Address
#                destinationIPv4Address
#                meanTcpRttMilliseconds
#                reverseMeanTcpRttMilliseconds"""
# 
# ielist = ipfix.ie.list(ipfix.ie.for_spec(x) for x in tuplespec.split())

reccount = 0
#for rec in r.tuple_iterator(ielist):
for rec in r.records_as_dict():
    print("--- record %u in message %u ---" % (reccount, r.msgcount))
    reccount += 1
    for key in rec:
         print("  %30s => %s" % (key, str(rec[key])))
    if reccount >= 100000:
        break

sys.stderr.write("read %u records from %u messages\n" %
                 (reccount, r.msgcount))
# prof.disable()
# prof.dump_stats("cprofile.out")