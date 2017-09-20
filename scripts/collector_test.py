#!/usr/bin/env python

import socketserver
import ipfix.reader
import ipfix.ie

import argparse

ap = argparse.ArgumentParser(description="Dump IPFIX files collected over TCP")
ap.add_argument('--spec', metavar='specfile', help='iespec file to read')
args = ap.parse_args()

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()
if args.spec:
    ipfix.ie.use_specfile(args.spec)


class CollectorDictHandler(socketserver.StreamRequestHandler):

    def handle(self):
        reccount = 0

        print ("connection from "+str(self.client_address))
        r = ipfix.reader.from_stream(self.rfile)
        for rec in r.records_as_dict():
            print("--- record %u in message %u from %s---" %
                  (reccount, r.msgcount, str(self.client_address)))
            reccount += 1
            for key in rec:
                 print("  %30s => %s" % (key, str(rec[key])))


ss = socketserver.TCPServer(("", 4739), CollectorDictHandler)
ss.serve_forever()
