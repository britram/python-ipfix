import bz2
import gzip
import io
import struct
from ipaddress import ip_address

import pytest

import ipfix.cli as cli
import ipfix.ie as ie
import ipfix.ieutils as ieutils
import ipfix.testutils as testutils


@pytest.fixture(autouse=True)
def setup_iana():
    ie.clear_infomodel()
    ie.use_iana_default()
    yield
    ie.clear_infomodel()


def test_ieutils_csv_xml_reverse_and_write(tmp_path):
    csv_data = io.StringIO(
        "ElementID,Name,Abstract Data Type,Status\n"
        "1,octetDeltaCount,unsigned64,current\n"
        "520,tcpOptionsFull,unsigned256,current\n"
        "291,basicListExample,basicList,current\n"
        "0,Reserved,,\n"
    )
    specs = ieutils.parse_iana_csv(csv_data)
    assert specs == [
        "octetDeltaCount(1)<unsigned64>[8]",
        "tcpOptionsFull(520)<unsigned256>[32]",
    ]

    xml_data = io.BytesIO(
        b'<registry xmlns="http://www.iana.org/assignments">'
        b'  <registry id="ipfix-information-elements">'
        b"    <record>"
        b"      <elementId>1</elementId>"
        b"      <name>octetDeltaCount</name>"
        b"      <dataType>unsigned64</dataType>"
        b"    </record>"
        b"    <record>"
        b"      <elementId>291</elementId>"
        b"      <name>basicListExample</name>"
        b"      <dataType>basicList</dataType>"
        b"    </record>"
        b"  </registry>"
        b"</registry>"
    )
    assert ieutils.parse_iana_xml(xml_data) == ["octetDeltaCount(1)<unsigned64>[8]"]

    assert (
        ieutils.reverse_iespec("octetDeltaCount(1)<unsigned64>[8]")
        == "reverseOctetDeltaCount(29305/1)<unsigned64>[8]"
    )
    assert (
        ieutils.reverse_iespec("myMetric(35566/5)<unsigned32>[4]")
        == "reverseMyMetric(35566/16389)<unsigned32>[4]"
    )
    assert ieutils.is_reversible_ie("octetDeltaCount") is True
    assert ieutils.is_reversible_ie("sourceIPv4Address") is False
    assert ieutils.is_reversible_ie("messageScope") is False

    out = tmp_path / "out.iespec"
    ieutils.write_specfile(out, specs)
    assert out.read_text(encoding="utf-8").splitlines() == specs


def test_cli_ipfix2csv_and_ipfixstat(tmp_path, capsys):
    raw = testutils._stored_test_message
    plain_file = tmp_path / "test.ipfix"
    gz_file = tmp_path / "test.ipfix.gz"
    bz2_file = tmp_path / "test.ipfix.bz2"
    plain_file.write_bytes(raw)
    with gzip.open(gz_file, "wb") as f:
        f.write(raw)
    with bz2.open(bz2_file, "wb") as f:
        f.write(raw)

    # stream_to_csv directly
    out = io.StringIO()
    cli.stream_to_csv(
        io.BytesIO(raw), ["sourceIPv4Address", "packetDeltaCount"], outstream=out
    )
    lines = out.getvalue().strip().splitlines()
    assert len(lines) == 129  # header + 128 records
    assert '"sourceIPv4Address","packetDeltaCount"' in lines[0]

    # main_ipfix2csv with plain, gzip, bzip2
    for flag, path in [
        ([], plain_file),
        (["-z"], gz_file),
        (["-j"], bz2_file),
    ]:
        cli.main_ipfix2csv([*flag, "-f", str(path), "sourceIPv4Address", "packetDeltaCount"])
        captured = capsys.readouterr().out.splitlines()
        assert len(captured) == 129

    # Invalid argument combinations
    with pytest.raises(ValueError):
        cli.main_ipfix2csv(["-9", "-c", "tcp", "sourceIPv4Address"])
    with pytest.raises(ValueError):
        cli.main_ipfix2csv(["-z", "sourceIPv4Address"])
    with pytest.raises(ValueError):
        cli.main_ipfix2csv(["-c", "sctp", "sourceIPv4Address"])

    # main_ipfixstat with plain, gzip, bzip2
    for flag, path in [
        ([], plain_file),
        (["-z"], gz_file),
        (["-j"], bz2_file),
    ]:
        cli.main_ipfixstat([*flag, "-f", str(path)])
        report = capsys.readouterr().out
        assert "1 templates, 1 template sets, 1 decodable sets" in report
        assert "Template 257 in domain 8304" in report

    # NetFlow v9 via ipfixstat
    tset = struct.pack("!HH HH HH", 0, 12, 256, 1, 8, 4)
    dset = struct.pack("!HH 4s", 256, 8, ip_address("10.0.0.1").packed)
    v9_raw = struct.pack("!HHLLLL", 9, 1, 1000, 1700000000, 1, 7) + tset + dset
    v9_file = tmp_path / "test.v9"
    v9_file.write_bytes(v9_raw)
    cli.main_ipfixstat(["-9", "-f", str(v9_file)])
    v9_report = capsys.readouterr().out
    assert "Template 256 in domain 7" in v9_report
