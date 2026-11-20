# python-ipfix

IPFIX (RFC 7011) implementation for Python 3.11+.

This package provides a Python interface to IPFIX message streams, and tools
for building IPFIX Exporting and Collecting Processes. It handles message
framing and deframing, encoding and decoding IPFIX data records using
templates, a bridge between IPFIX abstract data types (ADTs) and native Python
data types, and a read-only NetFlow v9 PDU decoder.

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

Command-line utilities `ipfix2csv` and `ipfixstat` are installed as console
scripts.

## Development

```bash
uv sync --group dev
uv run ruff check ipfix tests
uv run pytest
```

## License

GNU Lesser General Public License v3 or later (LGPLv3+).
