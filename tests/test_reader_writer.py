import io
from datetime import datetime
from ipaddress import ip_address

import pytest

import ipfix.ie as ie
import ipfix.reader as reader
import ipfix.template as template
import ipfix.writer as writer


@pytest.fixture(autouse=True)
def setup_iana():
    ie.clear_infomodel()
    ie.use_iana_default()
    yield
    ie.clear_infomodel()


def test_writer_and_reader_multimessage_roundtrip():
    buf = io.BytesIO()
    # Small MTU forces multiple messages to be flushed automatically
    w = writer.to_stream(buf, mtu=128)
    w.set_domain(100)
    tmpl = template.for_specs(
        256,
        "flowStartMilliseconds",
        "sourceIPv4Address",
        "packetDeltaCount",
    )
    w.add_template(tmpl)
    w.set_export_template(256)

    expected = []
    for i in range(25):
        rec = {
            "flowStartMilliseconds": datetime(2024, 1, 1, 0, 0, i),
            "sourceIPv4Address": ip_address(0x0A000001 + i),
            "packetDeltaCount": i * 10,
        }
        expected.append(rec)
        if i % 2 == 0:
            w.export_namedict(rec)
        else:
            w.export_tuple(
                (
                    rec["flowStartMilliseconds"],
                    rec["sourceIPv4Address"],
                    rec["packetDeltaCount"],
                )
            )
    w.flush()
    assert w.msgcount > 1

    # Namedict stream read
    buf.seek(0)
    r = reader.from_stream(buf)
    got = list(r.namedict_iterator())
    assert got == expected
    assert r.msgcount == w.msgcount

    # Tuple stream read
    buf.seek(0)
    r2 = reader.from_stream(buf)
    ielist = ie.spec_list(["packetDeltaCount", "sourceIPv4Address"])
    tups = list(r2.tuple_iterator(ielist))
    assert tups == [
        (rec["packetDeltaCount"], rec["sourceIPv4Address"]) for rec in expected
    ]
    assert r2.msgcount == w.msgcount


def test_writer_set_domain_and_flush_edge_cases():
    buf = io.BytesIO()
    w = writer.to_stream(buf, mtu=96)
    w.set_domain(1)
    # Flush right after begin_export (empty message, cursetid is None) is a no-op
    w.flush()
    assert w.msgcount == 0

    t1 = template.for_specs(256, "sourceIPv4Address", "packetDeltaCount")
    w.add_template(t1)
    w.set_export_template(256)
    w.export_namedict(
        {"sourceIPv4Address": ip_address("192.0.2.1"), "packetDeltaCount": 1}
    )

    # Switching domain flushes previous domain and increments msgcount
    prev_count = w.msgcount
    w.set_domain(2)
    assert w.msgcount == prev_count + 1

    t2 = template.for_specs(257, "sourceIPv4Address", "octetDeltaCount")
    w.add_template(t2)
    w.set_export_template(257)
    w.export_namedict(
        {"sourceIPv4Address": ip_address("192.0.2.2"), "octetDeltaCount": 500}
    )
    w.flush()

    buf.seek(0)
    r = reader.from_stream(buf)
    recs = list(r.namedict_iterator())
    assert len(recs) == 2
    assert recs[0]["packetDeltaCount"] == 1
    assert recs[1]["octetDeltaCount"] == 500


def test_writer_without_set_domain_and_no_empty_sets():
    buf = io.BytesIO()
    w = writer.to_stream(buf, mtu=64)
    t1 = template.for_specs(256, "sourceIPv4Address", "packetDeltaCount")
    # Using writer without calling set_domain() defaults to ODID 0
    w.add_template(t1)
    w.flush()
    w.set_export_template(256)
    w.export_namedict(
        {"sourceIPv4Address": ip_address("10.0.0.1"), "packetDeltaCount": 1}
    )
    w.flush()

    # After set_domain(), exporting without set_export_template() raises IpfixEncodeError
    w.set_domain(5)
    with pytest.raises(writer.message.IpfixEncodeError):
        w.export_namedict(
            {"sourceIPv4Address": ip_address("10.0.0.2"), "packetDeltaCount": 2}
        )

    # Verify wire stream has no empty 4-byte sets and preserves ODID 0
    buf.seek(0)
    r = reader.from_stream(buf)
    r.msg.read_message(buf)
    assert r.msg.odid == 0
    assert [(sid, slen) for _, sid, slen in r.msg.setlist] == [(2, 16)]
    r.msg.read_message(buf)
    assert [(sid, slen) for _, sid, slen in r.msg.setlist] == [(256, 16)]

    buf.seek(0)
    recs = list(reader.from_stream(buf).namedict_iterator())
    assert recs == [
        {"sourceIPv4Address": ip_address("10.0.0.1"), "packetDeltaCount": 1}
    ]
