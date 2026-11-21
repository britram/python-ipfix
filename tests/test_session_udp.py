from ipaddress import ip_address

import pytest

import ipfix.ie as ie
import ipfix.message as message
import ipfix.reader as reader
import ipfix.session as session
import ipfix.template as template
import ipfix.writer as writer


@pytest.fixture(autouse=True)
def setup_iana():
    ie.clear_infomodel()
    ie.use_iana_default()
    yield
    ie.clear_infomodel()


def test_session_shared_across_message_buffers():
    """Issues #13, #27, #31: template in packet 1, data in packet 2 via shared Session."""
    tmpl = template.for_specs(256, "sourceIPv4Address", "packetDeltaCount")

    # Packet 1: template only
    exp = message.MessageBuffer()
    exp.begin_export(42)
    exp.add_template(tmpl, export=True)
    pkt1 = exp.to_bytes()

    # Packet 2: data only (no template re-sent)
    exp.begin_export(42)
    exp.export_ensure_set(256)
    exp.export_namedict(
        {"sourceIPv4Address": ip_address("198.51.100.1"), "packetDeltaCount": 7}
    )
    pkt2 = exp.to_bytes()

    # Collector uses fresh MessageBuffers sharing a single Session
    sess = session.Session()
    m1 = message.MessageBuffer(session=sess)
    m1.from_bytes(pkt1)
    assert list(m1.namedict_iterator()) == []

    m2 = message.MessageBuffer(session=sess)
    m2.from_bytes(pkt2)
    assert list(m2.namedict_iterator()) == [
        {"sourceIPv4Address": ip_address("198.51.100.1"), "packetDeltaCount": 7}
    ]


def test_session_template_expiration():
    tmpl = template.for_specs(256, "sourceIPv4Address")
    sess = session.Session(template_lifetime=10.0)
    sess.add_template(1, tmpl, now=100.0)
    assert sess.get_template(1, 256, now=105.0) is tmpl
    assert list(sess.active_template_ids(1, now=105.0)) == [256]

    # Expired after 10s
    with pytest.raises(KeyError):
        sess.get_template(1, 256, now=111.0)
    assert list(sess.active_template_ids(1, now=111.0)) == []

    # purge_expired_templates removes expired entries
    sess.add_template(1, tmpl, now=200.0)
    assert sess.purge_expired_templates(now=205.0) == 0
    assert sess.purge_expired_templates(now=215.0) == 1

    sess.reset()
    assert sess.templates == {}


def test_session_sequence_gap_detection():
    """Issue #5: collector-side sequence number verification."""
    gaps = []
    sess = session.Session(
        sequence_gap_hook=lambda s, odid, sid, exp, got: gaps.append((odid, exp, got))
    )

    tmpl = template.for_specs(256, "packetDeltaCount")
    exp = message.MessageBuffer()

    # Message 1: seq 0, 2 records -> next expected seq is 2
    exp.begin_export(9)
    exp.add_template(tmpl)
    exp.export_ensure_set(256)
    exp.export_namedict({"packetDeltaCount": 1})
    exp.export_namedict({"packetDeltaCount": 2})
    pkt1 = exp.to_bytes()

    # Message 2: seq 2, 1 record (in-order) -> next expected seq is 3
    exp.begin_export(9)
    exp.export_ensure_set(256)
    exp.export_namedict({"packetDeltaCount": 3})
    pkt2 = exp.to_bytes()

    # Message 3: dropped!
    exp.begin_export(9)
    exp.export_ensure_set(256)
    exp.export_namedict({"packetDeltaCount": 4})
    _ = exp.to_bytes()

    # Message 4: seq 4 (gap: expected 3, got 4)
    exp.begin_export(9)
    exp.export_ensure_set(256)
    exp.export_namedict({"packetDeltaCount": 5})
    pkt4 = exp.to_bytes()

    for pkt in (pkt1, pkt2, pkt4):
        m = message.MessageBuffer(session=sess)
        m.from_bytes(pkt)
        list(m.namedict_iterator())

    assert gaps == [(9, 3, 4)]


def test_datagram_writer_and_reader_udp_roundtrip():
    """Issues #22, #27, #31: DatagramWriter with template refresh + DatagramReader per peer."""
    sent = []
    dw = writer.DatagramWriter(
        sent.append, mtu=128, template_refresh_interval=10.0
    )
    dw.set_domain(10)
    tmpl = template.for_specs(256, "sourceIPv4Address", "packetDeltaCount")
    dw.add_template(tmpl)
    dw.set_export_template(256)

    for i in range(15):
        dw.export_namedict(
            {"sourceIPv4Address": ip_address(0x0A000001 + i), "packetDeltaCount": i}
        )
    # Trigger explicit template refresh
    dw.refresh_templates()
    dw.export_tuple((ip_address("10.0.0.99"), 99))
    dw.flush()

    assert len(sent) >= 2
    assert all(len(d) <= 128 for d in sent)

    dr = reader.DatagramReader(template_lifetime=600.0)
    peer_a = ("192.0.2.10", 12345)
    recs = []
    for dgram in sent:
        recs.extend(dr.namedict_iterator(dgram, peer=peer_a))

    assert len(recs) == 16
    assert recs[-1]["packetDeltaCount"] == 99

    # Peer B has an isolated Session and shouldn't decode data-only datagram sent[1]
    peer_b = ("192.0.2.20", 54321)
    assert list(dr.namedict_iterator(sent[1], peer=peer_b)) == []

    # Tuple iterator on DatagramReader
    ielist = ie.spec_list(["packetDeltaCount"])
    tups = list(dr.tuple_iterator(sent[-1], ielist, peer=peer_a))
    assert (99,) in tups


def test_repeated_ies_in_template_issue10():
    """Issue #10: multiple occurrences of the same IE in a single template."""
    tmpl = template.for_specs(
        256,
        "sourceIPv4Address",
        "mplsTopLabelStackSection",
        "mplsTopLabelStackSection",
        "packetDeltaCount",
    )

    msg = message.MessageBuffer()
    msg.begin_export(1)
    msg.add_template(tmpl)
    msg.export_ensure_set(256)

    rec_in = {
        "sourceIPv4Address": ip_address("10.0.0.1"),
        "mplsTopLabelStackSection": [b"\x00\x01\x00", b"\x00\x02\x01"],
        "packetDeltaCount": 42,
    }
    msg.export_namedict(rec_in)
    raw = msg.to_bytes()

    msg2 = message.MessageBuffer()
    msg2.from_bytes(raw)
    assert list(msg2.namedict_iterator()) == [rec_in]

    # Tuple iterator requesting both repeated occurrences
    ielist = ie.spec_list(
        ["mplsTopLabelStackSection", "mplsTopLabelStackSection", "packetDeltaCount"]
    )
    assert list(msg2.tuple_iterator(ielist)) == [
        (b"\x00\x01\x00", b"\x00\x02\x01", 42)
    ]

    # Requesting 3 occurrences when template only has 2 skips the template
    ielist3 = ie.spec_list(
        [
            "mplsTopLabelStackSection",
            "mplsTopLabelStackSection",
            "mplsTopLabelStackSection",
        ]
    )
    assert list(msg2.tuple_iterator(ielist3)) == []

    # 3 repeated occurrences in a single template exercises list append path
    tmpl3 = template.for_specs(
        257,
        "mplsTopLabelStackSection",
        "mplsTopLabelStackSection",
        "mplsTopLabelStackSection",
    )
    msg3 = message.MessageBuffer()
    msg3.begin_export(1)
    msg3.add_template(tmpl3)
    msg3.export_ensure_set(257)
    rec3 = {"mplsTopLabelStackSection": [b"\x00\x01\x00", b"\x00\x02\x00", b"\x00\x03\x01"]}
    msg3.export_namedict(rec3)
    msg4 = message.MessageBuffer()
    msg4.from_bytes(msg3.to_bytes())
    assert list(msg4.namedict_iterator()) == [rec3]


def test_datagram_writer_auto_refresh_and_set_domain():
    sent = []
    dw = writer.DatagramWriter(sent.append, mtu=128, template_refresh_interval=0.0)
    dw.set_domain(1)
    # Empty flush is a no-op
    dw.flush()
    assert dw.msgcount == 0

    tmpl = template.for_specs(256, "sourceIPv4Address", "packetDeltaCount")
    dw.add_template(tmpl)
    dw.set_export_template(256)
    # With template_refresh_interval=0.0, export triggers automatic template refresh
    dw.export_namedict(
        {"sourceIPv4Address": ip_address("192.0.2.1"), "packetDeltaCount": 1}
    )
    # Switching domain flushes domain 1
    dw.set_domain(2)
    assert dw.msgcount >= 1
    assert len(sent) == dw.msgcount

    # DatagramReader with explicit shared Session
    shared = session.Session()
    dr = reader.DatagramReader(session=shared)
    assert dr.session_for_peer(("1.2.3.4", 1)) is shared
    assert dr.session_for_peer(("5.6.7.8", 2)) is shared
