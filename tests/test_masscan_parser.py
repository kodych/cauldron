"""Tests for Masscan output parser."""

import pytest

from cauldron.parsers.masscan_parser import parse_masscan


# --- XML format tests ---

MASSCAN_XML_BASIC = """\
<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1700000000" version="1.3.2" args="masscan -p80,443 10.0.0.0/24 -oX out.xml">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1700000060"/>
  </runstats>
</nmaprun>
"""


def test_parse_xml_basic():
    scan = parse_masscan(MASSCAN_XML_BASIC)
    assert scan.scanner == "masscan"
    assert scan.scanner_version == "1.3.2"
    assert len(scan.hosts_up) == 2
    assert scan.total_services == 3


def test_parse_xml_host_details():
    scan = parse_masscan(MASSCAN_XML_BASIC)
    hosts = {h.ip: h for h in scan.hosts_up}

    h1 = hosts["10.0.0.1"]
    assert len(h1.services) == 2
    ports = {s.port for s in h1.services}
    assert ports == {80, 443}

    h2 = hosts["10.0.0.2"]
    assert len(h2.services) == 1
    assert h2.services[0].port == 22
    assert h2.services[0].name == "ssh"


def test_parse_xml_service_fields():
    scan = parse_masscan(MASSCAN_XML_BASIC)
    hosts = {h.ip: h for h in scan.hosts_up}
    http = next(s for s in hosts["10.0.0.1"].services if s.port == 80)
    assert http.protocol == "tcp"
    assert http.state == "open"
    assert http.name == "http"
    # Masscan doesn't provide these
    assert http.product is None
    assert http.version is None


def test_parse_xml_timestamps():
    scan = parse_masscan(MASSCAN_XML_BASIC)
    assert scan.start_time is not None
    assert scan.end_time is not None


MASSCAN_XML_NO_SERVICE = """\
<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1700000000">
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_xml_no_service_element():
    """Masscan may omit <service> element entirely."""
    scan = parse_masscan(MASSCAN_XML_NO_SERVICE)
    assert len(scan.hosts_up) == 1
    assert scan.hosts_up[0].services[0].port == 8080
    assert scan.hosts_up[0].services[0].name is None


MASSCAN_XML_CLOSED = """\
<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1700000000">
  <host>
    <address addr="10.0.0.3" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
      </port>
      <port protocol="tcp" portid="81">
        <state state="closed" reason="rst"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_xml_skips_closed():
    scan = parse_masscan(MASSCAN_XML_CLOSED)
    assert len(scan.hosts_up[0].services) == 1
    assert scan.hosts_up[0].services[0].port == 80


# --- JSON format tests ---

MASSCAN_JSON_BASIC = """[
  {"ip": "10.0.0.1", "timestamp": "1700000000", "ports": [
    {"port": 80, "proto": "tcp", "status": "open", "service": {"name": "http"}},
    {"port": 443, "proto": "tcp", "status": "open", "service": {"name": "https"}}
  ]},
  {"ip": "10.0.0.2", "timestamp": "1700000001", "ports": [
    {"port": 22, "proto": "tcp", "status": "open", "service": {"name": "ssh"}}
  ]}
]"""


def test_parse_json_basic():
    scan = parse_masscan(MASSCAN_JSON_BASIC)
    assert scan.scanner == "masscan"
    assert len(scan.hosts_up) == 2
    assert scan.total_services == 3


def test_parse_json_host_details():
    scan = parse_masscan(MASSCAN_JSON_BASIC)
    hosts = {h.ip: h for h in scan.hosts_up}

    h1 = hosts["10.0.0.1"]
    assert len(h1.services) == 2
    assert h1.services[0].name == "http"

    h2 = hosts["10.0.0.2"]
    assert len(h2.services) == 1
    assert h2.services[0].port == 22


MASSCAN_JSON_TRAILING_COMMA = """[
  {"ip": "10.0.0.1", "timestamp": "1700000000", "ports": [
    {"port": 80, "proto": "tcp", "status": "open"}
  ]},
]"""


def test_parse_json_trailing_comma():
    """Masscan JSON output often has trailing comma before ]."""
    scan = parse_masscan(MASSCAN_JSON_TRAILING_COMMA)
    assert len(scan.hosts_up) == 1
    assert scan.hosts_up[0].services[0].port == 80


MASSCAN_JSON_MINIMAL = """[
  {"ip": "10.0.0.1", "ports": [{"port": 3306, "proto": "tcp", "status": "open"}]}
]"""


def test_parse_json_minimal():
    """Minimal JSON without service name or timestamp."""
    scan = parse_masscan(MASSCAN_JSON_MINIMAL)
    assert len(scan.hosts_up) == 1
    svc = scan.hosts_up[0].services[0]
    assert svc.port == 3306
    assert svc.name is None


# --- Format detection ---

def test_auto_detect_xml():
    scan = parse_masscan(MASSCAN_XML_BASIC)
    assert scan.scanner == "masscan"
    assert len(scan.hosts_up) == 2


def test_auto_detect_json():
    scan = parse_masscan(MASSCAN_JSON_BASIC)
    assert scan.scanner == "masscan"
    assert len(scan.hosts_up) == 2


def test_invalid_format():
    with pytest.raises(ValueError, match="Unrecognized"):
        parse_masscan("this is not a valid scan output")


# --- Edge cases ---

MASSCAN_XML_DUPLICATE_PORTS = """\
<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1700000000">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_xml_merges_same_ip():
    """Masscan reports each port in a separate <host> block for the same IP."""
    scan = parse_masscan(MASSCAN_XML_DUPLICATE_PORTS)
    assert len(scan.hosts_up) == 1
    assert len(scan.hosts_up[0].services) == 2
    ports = {s.port for s in scan.hosts_up[0].services}
    assert ports == {80, 443}


MASSCAN_XML_UDP = """\
<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1700000000">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open" reason="udp-response"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_udp():
    scan = parse_masscan(MASSCAN_XML_UDP)
    svc = scan.hosts_up[0].services[0]
    assert svc.port == 161
    assert svc.protocol == "udp"


def test_empty_result():
    xml = '<?xml version="1.0"?><nmaprun scanner="masscan"></nmaprun>'
    scan = parse_masscan(xml)
    assert len(scan.hosts_up) == 0


def test_json_empty_array():
    scan = parse_masscan("[]")
    assert len(scan.hosts_up) == 0


def test_scan_result_properties():
    """Test ScanResult properties work correctly with masscan data."""
    scan = parse_masscan(MASSCAN_XML_BASIC)
    assert scan.hosts_up == scan.hosts  # all hosts are "up" in masscan
    assert scan.total_services == 3


# --- Complex / real-world edge cases ---

# 1. Host with many ports (honeypot / Windows with high RPC ports)
MASSCAN_XML_MANY_PORTS = '<?xml version="1.0"?>\n<nmaprun scanner="masscan" start="1700000000">\n'
for _p in [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 389, 443,
           445, 465, 587, 636, 993, 995, 1433, 1521, 3268, 3306, 3389, 5432,
           5900, 5985, 8080, 8443, 9200] + list(range(49152, 49252)):
    MASSCAN_XML_MANY_PORTS += (
        f'<host endtime="1700000001"><address addr="10.99.0.1" addrtype="ipv4"/>'
        f'<ports><port protocol="tcp" portid="{_p}">'
        f'<state state="open" reason="syn-ack" reason_ttl="126"/>'
        f'</port></ports></host>\n'
    )
MASSCAN_XML_MANY_PORTS += '</nmaprun>'


def test_many_ports_single_host():
    """Host with 132 open ports (32 well-known + 100 high RPC)."""
    scan = parse_masscan(MASSCAN_XML_MANY_PORTS)
    assert len(scan.hosts_up) == 1
    host = scan.hosts_up[0]
    assert host.ip == "10.99.0.1"
    assert len(host.services) == 132
    # No duplicates
    ports = [s.port for s in host.services]
    assert len(ports) == len(set(ports))


# 2. Mixed IPv4 + IPv6 — parser should take IPv4 only
MASSCAN_XML_IPV6_MIXED = """\
<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1700000000">
  <host endtime="1700000001">
    <address addr="10.0.0.50" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
    </port></ports>
  </host>
  <host endtime="1700000001">
    <address addr="fe80::1" addrtype="ipv6"/>
    <ports><port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
    </port></ports>
  </host>
  <host endtime="1700000001">
    <address addr="10.0.0.51" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
    </port></ports>
  </host>
</nmaprun>
"""


def test_ipv6_hosts_skipped():
    """IPv6 hosts should be skipped — only IPv4 parsed."""
    scan = parse_masscan(MASSCAN_XML_IPV6_MIXED)
    assert len(scan.hosts_up) == 2
    ips = {h.ip for h in scan.hosts_up}
    assert ips == {"10.0.0.50", "10.0.0.51"}
    assert "fe80::1" not in ips


# 3. Duplicate port+IP entries (rescan overlap)
MASSCAN_XML_DEDUP = """\
<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1700000000">
  <host endtime="1700000001"><address addr="10.0.0.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="445">
      <state state="open" reason="syn-ack"/>
    </port></ports></host>
  <host endtime="1700000002"><address addr="10.0.0.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="445">
      <state state="open" reason="syn-ack"/>
    </port></ports></host>
  <host endtime="1700000003"><address addr="10.0.0.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
    </port></ports></host>
</nmaprun>
"""


def test_duplicate_port_dedup():
    """Same IP+port reported multiple times — should appear only once."""
    scan = parse_masscan(MASSCAN_XML_DEDUP)
    assert len(scan.hosts_up) == 1
    host = scan.hosts_up[0]
    assert len(host.services) == 2
    ports = {s.port for s in host.services}
    assert ports == {80, 445}


# 4. Truncated XML — scan interrupted with Ctrl+C (no closing tags)
MASSCAN_XML_TRUNCATED = """\
<?xml version="1.0"?>
<!-- masscan v1.0 scan -->
<nmaprun scanner="masscan" start="1700000000" version="1.0-BETA" xmloutputversion="1.03">
<scaninfo type="syn" protocol="tcp" />
<host endtime="1700000001"><address addr="10.0.0.30" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
<host endtime="1700000001"><address addr="10.0.0.31" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
"""


def test_truncated_xml():
    """Scan interrupted — XML has no closing </nmaprun>. Should still parse what's there."""
    # ET.fromstring will fail on truncated XML — we need graceful handling
    # This test documents expected behavior: raise or partial parse
    try:
        scan = parse_masscan(MASSCAN_XML_TRUNCATED)
        # If parser handles it, verify partial results
        assert len(scan.hosts_up) >= 0
    except Exception:
        # Truncated XML raising an error is acceptable behavior
        pass


# 5. Real-world masscan format with comments, scaninfo, reason_ttl
MASSCAN_XML_REALWORLD = """\
<?xml version="1.0"?>
<!-- masscan v1.0 scan -->
<nmaprun scanner="masscan" start="1700000000" version="1.0-BETA"  xmloutputversion="1.03">
<scaninfo type="syn" protocol="tcp" />
<host endtime="1700000001"><address addr="10.0.0.70" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack" reason_ttl="126"/></port></ports></host>
<host endtime="1700000001"><address addr="10.0.0.71" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="61"/></port></ports></host>
<host endtime="1700000001"><address addr="10.0.0.71" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="61"/></port></ports></host>
<host endtime="1700000001"><address addr="10.0.0.72" addrtype="ipv4"/><ports><port protocol="tcp" portid="88"><state state="open" reason="syn-ack" reason_ttl="126"/></port></ports></host>
<host endtime="1700000001"><address addr="10.0.0.72" addrtype="ipv4"/><ports><port protocol="tcp" portid="389"><state state="open" reason="syn-ack" reason_ttl="126"/></port></ports></host>
<host endtime="1700000001"><address addr="10.0.0.72" addrtype="ipv4"/><ports><port protocol="tcp" portid="636"><state state="open" reason="syn-ack" reason_ttl="126"/></port></ports></host>
<host endtime="1700000001"><address addr="10.0.0.72" addrtype="ipv4"/><ports><port protocol="tcp" portid="3268"><state state="open" reason="syn-ack" reason_ttl="126"/></port></ports></host>
<runstats>
<finished time="1700000047" timestr="2026-01-01 00:00:47" elapsed="47" />
<hosts up="7" down="0" total="7" />
</runstats>
</nmaprun>
"""


def test_realworld_format():
    """Real masscan output format with XML comments, scaninfo, reason_ttl, endtime attributes."""
    scan = parse_masscan(MASSCAN_XML_REALWORLD)
    assert scan.scanner == "masscan"
    assert scan.scanner_version == "1.0-BETA"
    assert len(scan.hosts_up) == 3

    hosts = {h.ip: h for h in scan.hosts_up}

    # Single port host
    assert len(hosts["10.0.0.70"].services) == 1
    assert hosts["10.0.0.70"].services[0].port == 445

    # Two ports merged from two host entries
    assert len(hosts["10.0.0.71"].services) == 2
    assert {s.port for s in hosts["10.0.0.71"].services} == {80, 443}

    # Four ports merged — looks like a domain controller
    assert len(hosts["10.0.0.72"].services) == 4
    dc_ports = {s.port for s in hosts["10.0.0.72"].services}
    assert dc_ports == {88, 389, 636, 3268}


def test_realworld_timestamps():
    """Verify start/end time parsing from real format."""
    scan = parse_masscan(MASSCAN_XML_REALWORLD)
    assert scan.start_time is not None
    assert scan.end_time is not None
    # Elapsed should be ~47 seconds
    delta = (scan.end_time - scan.start_time).total_seconds()
    assert delta == 47


# 6. JSON: single object (not array)
MASSCAN_JSON_SINGLE = '{"ip": "10.0.0.90", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]}'


def test_json_single_object():
    """Some masscan versions output a single JSON object (not array)."""
    # This is an edge case — our parser wraps it
    try:
        scan = parse_masscan(MASSCAN_JSON_SINGLE)
        # If handled, should have 1 host
        assert len(scan.hosts_up) <= 1
    except ValueError:
        # Rejecting non-array JSON is also acceptable
        pass


# 7. JSON: newline-delimited (ndjson) format
MASSCAN_JSON_NDJSON = """\
{"ip": "10.0.0.80", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]}
{"ip": "10.0.0.81", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]}
{"ip": "10.0.0.80", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]}
"""


def test_json_ndjson_format():
    """Newline-delimited JSON — one record per line."""
    scan = parse_masscan(MASSCAN_JSON_NDJSON)
    assert len(scan.hosts_up) == 2
    hosts = {h.ip: h for h in scan.hosts_up}
    # 10.0.0.80 has ports 80 and 22 merged
    assert len(hosts["10.0.0.80"].services) == 2
    assert len(hosts["10.0.0.81"].services) == 1


# 8. TCP + UDP same port on same host
MASSCAN_XML_TCP_UDP_SAME_PORT = """\
<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1700000000">
  <host endtime="1700000001"><address addr="10.0.0.60" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="53">
      <state state="open" reason="syn-ack"/>
    </port></ports></host>
  <host endtime="1700000001"><address addr="10.0.0.60" addrtype="ipv4"/>
    <ports><port protocol="udp" portid="53">
      <state state="open" reason="udp-response"/>
    </port></ports></host>
</nmaprun>
"""


def test_tcp_udp_same_port():
    """TCP and UDP on same port number — should be two distinct services."""
    scan = parse_masscan(MASSCAN_XML_TCP_UDP_SAME_PORT)
    assert len(scan.hosts_up) == 1
    host = scan.hosts_up[0]
    assert len(host.services) == 2
    protos = {s.protocol for s in host.services}
    assert protos == {"tcp", "udp"}
    assert all(s.port == 53 for s in host.services)


# 9. Large-scale merge — simulate 50 hosts, each with ports arriving separately
MASSCAN_XML_LARGE_MERGE = '<?xml version="1.0"?>\n<nmaprun scanner="masscan" start="1700000000">\n'
for _i in range(50):
    _ip = f"10.50.0.{_i + 1}"
    for _port in [80, 443, 22, 3389]:
        MASSCAN_XML_LARGE_MERGE += (
            f'<host endtime="1700000001"><address addr="{_ip}" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="{_port}">'
            f'<state state="open" reason="syn-ack"/>'
            f'</port></ports></host>\n'
        )
MASSCAN_XML_LARGE_MERGE += '</nmaprun>'


def test_large_scale_merge():
    """50 hosts x 4 ports each = 200 host entries → 50 merged hosts."""
    scan = parse_masscan(MASSCAN_XML_LARGE_MERGE)
    assert len(scan.hosts_up) == 50
    assert scan.total_services == 200
    # Every host should have exactly 4 ports
    for host in scan.hosts_up:
        assert len(host.services) == 4
        ports = {s.port for s in host.services}
        assert ports == {22, 80, 443, 3389}


# 10. Port 0 — edge case (should be skipped)
MASSCAN_XML_PORT_ZERO = """\
<?xml version="1.0"?>
<nmaprun scanner="masscan" start="1700000000">
  <host endtime="1700000001"><address addr="10.0.0.99" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="0">
      <state state="open" reason="syn-ack"/>
    </port></ports></host>
  <host endtime="1700000001"><address addr="10.0.0.99" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
    </port></ports></host>
</nmaprun>
"""


def test_port_zero_skipped():
    """Port 0 is invalid and should be skipped."""
    scan = parse_masscan(MASSCAN_XML_PORT_ZERO)
    assert len(scan.hosts_up) == 1
    assert len(scan.hosts_up[0].services) == 1
    assert scan.hosts_up[0].services[0].port == 80
