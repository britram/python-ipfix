# python-ipfix

IPFIX (RFC 7011) implementation for Python 3.11+.

This package provides a Python interface to IPFIX message streams and UDP
datagrams, tools for building IPFIX Exporting and Collecting Processes, a
bridge between IPFIX abstract data types (ADTs) and native Python data types,
and a read-only NetFlow v9 PDU decoder.

## Installation

```bash
pip install ipfix
```

Requires Python 3.11 or later, with no mandatory runtime dependencies.

## Quick Start

```python
import ipfix.ie
import ipfix.message
import ipfix.template

ipfix.ie.use_iana_default()
ipfix.ie.use_5103_default()

msg = ipfix.message.MessageBuffer()
msg.begin_export(8304)
tmpl = ipfix.template.for_specs(
    256,
    "flowStartMilliseconds",
    "sourceIPv4Address",
    "destinationIPv4Address",
    "packetDeltaCount",
)
msg.add_template(tmpl)
msg.export_ensure_set(256)
```

For UDP collectors and exporters, use `ipfix.session.Session` with
`ipfix.reader.DatagramReader` and `ipfix.writer.DatagramWriter` so template
state, UDP template lifetimes, and periodic template refreshes are managed
automatically across datagrams.

Command-line utilities `ipfix2csv` (supporting files, TCP, and UDP) and
`ipfixstat` are installed as console scripts.

## Migrating from 0.x to 1.0

`v1.0.0` completes the modernization started in `v0.10.0` with a small set of
intentional breaking changes:

1. **Timezone-aware UTC `datetime` returns:**
   All decoded `dateTime*` Information Elements, `MessageBuffer.get_export_time()`,
   `ipfix.ie.InformationElement.parse()` for datetime types, and
   `ipfix.v9pdu.TimeAdapter` now return **timezone-aware UTC** `datetime`
   objects (`tzinfo=datetime.timezone.utc`) instead of naive `datetime`s.
   - Encoding (`export_*`) continues to accept both timezone-aware (converted
     to UTC) and naive (assumed UTC) `datetime` objects.
   - If your code compares or subtracts decoded timestamps against naive
     `datetime`s, update your reference timestamps to use `tzinfo=datetime.UTC`
     (or `datetime.now(datetime.UTC)`).
   - `dateTimeMicroseconds` and `dateTimeNanoseconds` now handle RFC 5905 NTP
     Era 1 rollover (February 7, 2036).
2. **Separated `Session` state & UDP helpers:**
   Templates, UDP template lifetimes, and sequence numbers now live in
   `ipfix.session.Session`. `MessageBuffer()` continues to create an internal
   default `Session` (and exposes `.templates` and `.sequences` properties) for
   backwards compatibility, so existing TCP/file code works unchanged. UDP
   collectors and exporters should migrate to `DatagramReader` /
   `DatagramWriter` (or pass a shared `Session` to `MessageBuffer(session=...)`).
3. **Repeated IEs in a single template:**
   If a template contains multiple occurrences of the same IE name (RFC 7011 §8),
   `namedict_iterator()` now returns a `list` of values under that key instead
   of silently overwriting earlier occurrences. Templates with unique IE names
   are unaffected.
4. **Fixed-length `string` encoding (introduced in `0.10.0`):**
   Encoding a UTF-8 string whose byte length exceeds a fixed-length `string[N]`
   field now raises `ValueError` instead of silently truncating mid-codepoint,
   and trailing `\x00` padding is stripped on decode.
5. **Python 3.11+ only:**
   Python 2.7 compatibility (`ipfix.compat`) and `vis-package` have been
   removed.

## Development

```bash
uv sync --group dev
uv run ruff check ipfix tests
uv run pytest
```

## License

GNU Lesser General Public License v3 or later (LGPLv3+).
