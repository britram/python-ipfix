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

"""Command-line entry points for ipfix2csv and ipfixstat."""

import argparse
import bz2
import csv
import gzip
import socketserver
import sys

from . import ie, message, reader, v9pdu


def _init_ipfix(specfiles=None):
    ie.use_iana_default()
    ie.use_5103_default()
    if specfiles:
        for sf in specfiles:
            ie.use_specfile(sf)


def _open_input(filename, use_gzip=False, use_bzip2=False):
    if use_bzip2:
        return bz2.open(filename, mode="rb")
    if use_gzip:
        return gzip.open(filename, mode="rb")
    return open(filename, mode="rb")


def stream_to_csv(instream, ienames, outstream=None, reader_fn=reader.from_stream):
    """Read an IPFIX or NetFlow v9 stream and write selected IEs as CSV."""
    if outstream is None:
        outstream = sys.stdout
    cols = ie.spec_list(ienames)
    r = reader_fn(instream)
    w = csv.writer(outstream, dialect="unix")
    w.writerow([e.name for e in cols])
    for rec in r.tuple_iterator(cols):
        w.writerow([col.unparse(val) for val, col in zip(rec, cols, strict=True)])


def main_ipfix2csv(argv=None):
    parser = argparse.ArgumentParser(
        description="Convert an IPFIX file or stream to CSV"
    )
    parser.add_argument("ienames", metavar="ie", nargs="+", help="column(s) by IE name")
    parser.add_argument(
        "--spec", "-s", metavar="specfile", action="append",
        help="file to load additional IESpecs from",
    )
    parser.add_argument(
        "--file", "-f", metavar="file", nargs="?",
        help="IPFIX file to read (default stdin)",
    )
    parser.add_argument(
        "--gzip", "-z", action="store_true",
        help="Decompress gzip-compressed IPFIX file",
    )
    parser.add_argument(
        "--bzip2", "-j", action="store_true",
        help="Decompress bz2-compressed IPFIX file",
    )
    parser.add_argument(
        "--netflow9", "-9", action="store_true",
        help="Decode as NetFlow version 9 instead of IPFIX (with --file or stdin only)",
    )
    parser.add_argument(
        "--collect", "-c", metavar="transport", nargs="?",
        help="run CP on specified transport",
    )
    parser.add_argument(
        "--bind", "-b", metavar="bind", nargs="?", default="",
        help="address to bind to as CP (default all)",
    )
    parser.add_argument(
        "--port", "-p", metavar="port", nargs="?", type=int, default=4739,
        help="port to bind to as CP (default 4739)",
    )
    args = parser.parse_args(argv)

    _init_ipfix(args.spec)
    reader_fn = v9pdu.from_stream if args.netflow9 else reader.from_stream

    if args.netflow9 and args.collect:
        raise ValueError("NetFlow9 only supported from files or stdin")
    if args.file is None and (args.bzip2 or args.gzip):
        raise ValueError("Decompression only supported from file input")

    if args.collect == "tcp":
        sys.stderr.write(
            f"starting TCP CP on {args.bind}:{args.port}; Ctrl-C to stop\n"
        )
        sys.stderr.flush()

        class TcpCsvHandler(socketserver.StreamRequestHandler):
            def handle(self):
                sys.stderr.write(f"connection from {self.client_address}\n")
                stream_to_csv(self.rfile, args.ienames)

        with socketserver.TCPServer((args.bind, args.port), TcpCsvHandler) as ss:
            ss.serve_forever()
    elif args.collect == "udp":
        sys.stderr.write(
            f"starting UDP CP on {args.bind}:{args.port}; Ctrl-C to stop\n"
        )
        sys.stderr.flush()
        cols = ie.spec_list(args.ienames)
        dg_reader = reader.DatagramReader()
        csv_writer = csv.writer(sys.stdout, dialect="unix")
        csv_writer.writerow([e.name for e in cols])
        sys.stdout.flush()

        class UdpCsvHandler(socketserver.DatagramRequestHandler):
            def handle(self):
                for rec in dg_reader.tuple_iterator(
                    self.packet, cols, peer=self.client_address
                ):
                    csv_writer.writerow(
                        [col.unparse(val) for val, col in zip(rec, cols, strict=True)]
                    )
                sys.stdout.flush()

        with socketserver.UDPServer((args.bind, args.port), UdpCsvHandler) as ss:
            ss.serve_forever()
    elif args.collect:
        raise ValueError(
            f"Unsupported transport {args.collect}; must be 'tcp' or 'udp'"
        )
    elif args.file:
        with _open_input(args.file, args.gzip, args.bzip2) as f:
            stream_to_csv(f, args.ienames, reader_fn=reader_fn)
    else:
        stream_to_csv(sys.stdin.buffer, args.ienames, reader_fn=reader_fn)


class TemplateStatsSession:
    """Collect template and dataset statistics over an IPFIX or NetFlow v9 stream."""

    def __init__(self, instream, netflow9=False):
        self.templates = {}
        self.template_count = {}
        self.template_replcount = {}
        self.template_setcount = {}
        self.template_bytecount = {}
        self.missing_setcount = {}
        self.missing_bytecount = {}

        if netflow9:
            self.r = v9pdu.from_stream(instream)
            self.r.template_record_hook = self.handle_template_record
            self.r.ignored_data_set_hook = self.handle_data_set
            self.r.unknown_data_set_hook = self.handle_unknown_set
        else:
            self.r = reader.from_stream(instream)
            self.r.msg.template_record_hook = self.handle_template_record
            self.r.msg.ignored_data_set_hook = self.handle_data_set
            self.r.msg.unknown_data_set_hook = self.handle_unknown_set

    def handle_template_record(self, msg, tmpl):
        if tmpl.count() == 0:
            return
        tkey = (msg.odid, tmpl.tid)
        if tkey in self.templates:
            self.template_count[tkey] += 1
            if not self.templates[tkey].identical_to(tmpl):
                self.template_replcount[tkey] += 1
                self.templates[tkey] = tmpl
        else:
            self.templates[tkey] = tmpl
            self.template_count[tkey] = 1
            self.template_replcount[tkey] = 0
            self.template_setcount[tkey] = 0
            self.template_bytecount[tkey] = 0

    def handle_data_set(self, msg, tmpl, setbuf):
        tkey = (msg.odid, tmpl.tid)
        self.template_setcount[tkey] += 1
        self.template_bytecount[tkey] += len(setbuf)

    def handle_unknown_set(self, msg, setbuf):
        setid, setlen = message._sethdr_st.unpack_from(setbuf)
        tkey = (msg.odid, setid)
        self.missing_setcount[tkey] = self.missing_setcount.get(tkey, 0) + 1
        self.missing_bytecount[tkey] = self.missing_bytecount.get(tkey, 0) + setlen

    def run(self):
        impossible = ie.spec_list(["impossible(35566/32767)<unsigned8>[1]"])
        for _ in self.r.tuple_iterator(impossible):
            pass

    def print_report(self, outstream=None):
        if outstream is None:
            outstream = sys.stdout
        missing_setcount = self.missing_setcount.copy()

        total_tsets = sum(self.template_count.values())
        total_dsets = sum(self.template_setcount.values())
        total_repl = sum(self.template_replcount.values())
        total_miss = sum(self.missing_setcount.values())

        outstream.write(
            f"#\n# {len(self.templates)} templates, {total_tsets} template sets, "
            f"{total_dsets} decodable sets, {total_repl} replacements, "
            f"{total_miss} missing sets total\n"
        )

        for tkey in sorted(self.templates.keys()):
            odid, _ = tkey
            tmpl = self.templates[tkey]
            kind = "Options Template" if tmpl.scopecount else "Template"
            outstream.write(
                f"#\n# {kind} {tmpl.tid} in domain {odid} ({len(tmpl.ies)} IEs)\n#\n"
            )
            for i, elem in enumerate(tmpl.ies):
                addl = "{scope}" if i < tmpl.scopecount else ""
                outstream.write(f"{elem}{addl}\n")
            outstream.write(
                f"# {self.template_count[tkey]} instances "
                f"{self.template_replcount[tkey]} replacements "
                f"{self.template_setcount[tkey]} sets "
                f"{self.template_bytecount[tkey]} bytes \n"
            )
            if tkey in missing_setcount:
                outstream.write(
                    f"# {missing_setcount[tkey]} sets missing template with this ID\n"
                )
                del missing_setcount[tkey]

        if missing_setcount:
            outstream.write("#\n# Sets without templates\n")
            for tkey, count in missing_setcount.items():
                outstream.write(
                    f"# {count} sets missing template with ID {tkey[1]} in domain {tkey[0]}\n"
                )


def main_ipfixstat(argv=None):
    parser = argparse.ArgumentParser(
        description="Dump statistics about templates and data sets in an IPFIX file"
    )
    parser.add_argument(
        "--spec", "-s", metavar="specfile", action="append",
        help="file to load additional IESpecs from",
    )
    parser.add_argument(
        "--file", "-f", metavar="file", nargs="?",
        help="IPFIX file to read (default stdin)",
    )
    parser.add_argument(
        "--gzip", "-z", action="store_true",
        help="Decompress gzip-compressed IPFIX file",
    )
    parser.add_argument(
        "--bzip2", "-j", action="store_true",
        help="Decompress bz2-compressed IPFIX file",
    )
    parser.add_argument(
        "--netflow9", "-9", action="store_true",
        help="Decode as NetFlow version 9 instead of IPFIX",
    )
    args = parser.parse_args(argv)

    _init_ipfix(args.spec)

    if args.file:
        with _open_input(args.file, args.gzip, args.bzip2) as f:
            tss = TemplateStatsSession(f, args.netflow9)
            tss.run()
    else:
        tss = TemplateStatsSession(sys.stdin.buffer, args.netflow9)
        tss.run()

    tss.print_report()
