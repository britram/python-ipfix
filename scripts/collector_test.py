#!/usr/bin/env python3

import argparse
import socketserver

import ipfix.ie
import ipfix.reader

ap = argparse.ArgumentParser(description="Dump IPFIX records collected over TCP")
ap.add_argument("--spec", metavar="specfile", help="iespec file to read")
args = ap.parse_args()

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()
if args.spec:
    ipfix.ie.use_specfile(args.spec)


class CollectorDictHandler(socketserver.StreamRequestHandler):
    def handle(self):
        reccount = 0

        print("connection from " + str(self.client_address))
        r = ipfix.reader.from_stream(self.rfile)
        for rec in r.namedict_iterator():
            print(
                f"--- record {reccount} in message {r.msgcount} from {self.client_address} ---"
            )
            reccount += 1
            for key, value in rec.items():
                print(f"  {key:>30s} => {value}")


with socketserver.TCPServer(("", 4739), CollectorDictHandler) as ss:
    ss.serve_forever()
