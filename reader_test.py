#!/usr/bin/env python3

import ipfix.reader
import ipfix.ie
import pprint
import argparse
import cProfile

ap = argparse.ArgumentParser(description="Dump an IPFIX file for debug purposes")
ap.add_argument('file', metavar='file', help='ipfix file to read')
ap.add_argument('--spec', metavar='specfile', help='iespec file to read')
args = ap.parse_args()

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()
if args.spec:
    ipfix.ie.load_specfile(args.spec)

prof = cProfile.Profile()
prof.enable()

r = ipfix.reader.from_stream(open(args.file, mode="rb"))

for rec in r.dict_iterator():
    print("--- record %u in message %u ---" % (r.reccount, r.msgcount))
    for key in rec:
        print("  %30s => %s" % (key, str(rec[key])))
    if r.reccount >= 100000:
        break

prof.disable()
prof.dump_stats("cprofile.out")