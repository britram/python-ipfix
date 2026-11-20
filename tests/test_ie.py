import ipaddress

import pytest

import ipfix.ie as ie
import ipfix.types as types


@pytest.fixture(autouse=True)
def clean_infomodel():
    ie.clear_infomodel()
    yield
    ie.clear_infomodel()


def test_iana_and_5103_2026_registry_loaded():
    ie.use_iana_default()
    ie.use_5103_default()

    # Classic IE
    e1 = ie.for_spec("octetDeltaCount")
    assert (e1.pen, e1.num, e1.length) == (0, 1, 8)

    # Modern 2026 IEs (RFC 9487, RFC 9740 unsigned256, RFC 9951)
    tcp_full = ie.for_spec("tcpOptionsFull")
    assert tcp_full.num == 520
    assert tcp_full.type.name == "unsigned256"
    assert tcp_full.length == 32

    udp_safe = ie.for_spec("udpSafeOptions")
    assert udp_safe.num == 525
    assert udp_safe.type.name == "unsigned256"

    delay = ie.for_spec("pathDelaySumDeltaMicroseconds")
    assert delay.num == 533
    assert delay.type.name == "unsigned64"

    # RFC 5103 reverse counterpart
    rev = ie.for_spec("reverseOctetDeltaCount")
    assert (rev.pen, rev.num) == (29305, 1)

    dumped = ie.dump_infomodel()
    assert len(dumped) > 900


def test_ie_equality_and_hash_invariant():
    ie.use_iana_default()
    a = ie.for_spec("octetDeltaCount")
    b = ie.for_spec("octetDeltaCount[4]")
    assert a.length == 8
    assert b.length == 4
    assert a == b
    assert hash(a) == hash(b)
    assert len({a, b}) == 1


def test_ie_list_hash_and_ordering():
    la = ie.InformationElementList(
        [ie.InformationElement(None, 35566, 9999, length=1)]
    )
    lb = ie.InformationElementList(
        [ie.InformationElement(None, 35566, 9999, length=4)]
    )
    lc = ie.InformationElementList([ie.InformationElement(None, 35566, 9998)])

    assert la[0].name == "_ipfix_35566_9999"
    assert la == lb
    assert la > lc
    assert len(la) == 1
    assert "35566/9999" in str(la)
    assert "InformationElementList" in repr(la)

    # Empty list hashable without AttributeError/TypeError
    empty = ie.InformationElementList()
    assert hash(empty) == hash(ie.InformationElementList())

    # Order-sensitive hash
    ie.use_iana_default()
    l1 = ie.spec_list(["octetDeltaCount", "packetDeltaCount"])
    l2 = ie.spec_list(["packetDeltaCount", "octetDeltaCount"])
    assert l1 != l2
    assert hash(l1) != hash(l2)
    assert l1.index(ie.for_spec("packetDeltaCount")) == 1


def test_unknown_template_entry_does_not_leak_globally():
    ie.use_iana_default()
    before = len(ie._ieForNum)

    elem = ie.for_template_entry(35566, 9999, 4)
    assert elem.name == "_ipfix_35566_9999"
    assert elem.length == 4
    assert elem.type.name == "octetArray"

    # Must NOT have been inserted into global registry
    assert len(ie._ieForNum) == before
    assert (35566, 9999) not in ie._ieForNum


def test_parse_unparse_and_custom_overrides():
    ie.use_iana_default()
    assert ie.for_spec("sourceIPv4Address").parse("192.0.2.19") == ipaddress.IPv4Address(
        "192.0.2.19"
    )
    # RLE and fixed-length string unparse/parse (regression for StructType arg bug)
    rle_ie = ie.for_spec("octetDeltaCount[4]")
    assert rle_ie.unparse(42) == "42"
    assert rle_ie.parse("42") == 42

    fixed_str = ie.for_spec("wlanSSID[14]")
    assert fixed_str.unparse("ietf") == "ietf"
    assert fixed_str.parse("ietf") == "ietf"

    custom = ie.InformationElement(
        "custom",
        35566,
        1,
        types.for_name("unsigned8"),
        valstr=lambda v: f"v={v}",
        valparse=lambda s: int(s.split("=")[1]),
    )
    assert custom.unparse(7) == "v=7"
    assert custom.parse("v=7") == 7
    assert custom.for_length(1).unparse(7) == "v=7"


def test_for_spec_errors_and_specfile(tmp_path):
    with pytest.raises(ValueError):
        ie.for_spec("")
    with pytest.raises(ValueError):
        ie.for_spec("not_a_known_ie")

    specfile = tmp_path / "custom.iespec"
    specfile.write_text(
        "# comment line\n\nmyCustomIE(35566/42)<unsigned32>[4]\n", encoding="utf-8"
    )
    ie.use_specfile(specfile)
    e = ie.for_spec("myCustomIE")
    assert (e.pen, e.num, e.length) == (35566, 42, 4)
