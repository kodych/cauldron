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
