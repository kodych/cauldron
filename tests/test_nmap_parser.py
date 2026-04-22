"""Tests for Nmap XML parser."""

from pathlib import Path

from cauldron.parsers.nmap_parser import parse_nmap_xml

SAMPLE_DIR = Path(__file__).parent.parent / "data" / "samples"


def test_parse_minimal_xml():
    """Test parsing a minimal valid Nmap XML."""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap -sV 10.0.0.1" start="1700000000" version="7.94">
        <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <hostnames><hostname name="server1.local" type="PTR"/></hostnames>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh" product="OpenSSH" version="8.9"/>
                </port>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http" product="Apache httpd" version="2.4.49"/>
                </port>
                <port protocol="tcp" portid="443">
                    <state state="open"/>
                    <service name="https" product="Apache httpd" version="2.4.49"/>
                </port>
            </ports>
        </host>
        <host>
            <status state="down"/>
            <address addr="10.0.0.2" addrtype="ipv4"/>
        </host>
        <runstats><finished time="1700000060"/></runstats>
    </nmaprun>
    """
    result = parse_nmap_xml(xml)

    assert result.scanner == "nmap"
    assert result.scanner_version == "7.94"
    assert len(result.hosts) == 2
    assert len(result.hosts_up) == 1

    host = result.hosts_up[0]
    assert host.ip == "10.0.0.1"
    assert host.hostname == "server1.local"
    assert len(host.services) == 3
    assert host.open_ports == [22, 80, 443]

    ssh = host.services[0]
    assert ssh.port == 22
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.9"


def test_parse_host_with_os_detection():
    """Test parsing OS detection info."""
    xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
        <host>
            <status state="up"/>
            <address addr="10.0.0.5" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Dell"/>
            <os>
                <osmatch name="Microsoft Windows Server 2019" accuracy="95"/>
            </os>
            <ports>
                <port protocol="tcp" portid="445">
                    <state state="open"/>
                    <service name="microsoft-ds"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """
    result = parse_nmap_xml(xml)
    host = result.hosts_up[0]

    assert host.os_name == "Microsoft Windows Server 2019"
    assert host.os_accuracy == 95
    assert host.mac == "AA:BB:CC:DD:EE:FF"
    assert host.mac_vendor == "Dell"


def test_parse_filtered_ports_included():
    """Filtered ports should be included (they indicate a firewall)."""
    xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
        <host>
            <status state="up"/>
            <address addr="10.0.0.10" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http"/>
                </port>
                <port protocol="tcp" portid="443">
                    <state state="filtered"/>
                    <service name="https"/>
                </port>
                <port protocol="tcp" portid="8080">
                    <state state="closed"/>
                    <service name="http-proxy"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """
    result = parse_nmap_xml(xml)
    host = result.hosts_up[0]

    # open and filtered included, closed excluded
    assert len(host.services) == 2
    assert host.services[0].state == "open"
    assert host.services[1].state == "filtered"


def test_parse_nse_scripts():
    """Test parsing NSE script output."""
    xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
        <host>
            <status state="up"/>
            <address addr="10.0.0.20" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="445">
                    <state state="open"/>
                    <service name="microsoft-ds"/>
                    <script id="smb-os-discovery" output="OS: Windows Server 2012 R2"/>
                    <script id="smb2-security-mode" output="Message signing enabled but not required"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """
    result = parse_nmap_xml(xml)
    host = result.hosts_up[0]
    smb = host.services[0]

    assert len(smb.scripts) == 2
    assert smb.scripts[0].script_id == "smb-os-discovery"
    assert "Windows Server 2012" in smb.scripts[0].output


def test_parse_traceroute():
    """Test parsing traceroute data."""
    xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
        <host>
            <status state="up"/>
            <address addr="10.0.1.100" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http"/>
                </port>
            </ports>
            <trace>
                <hop ttl="1" ipaddr="10.0.0.1" rtt="1.50" host="gateway.local"/>
                <hop ttl="2" ipaddr="10.0.1.1" rtt="3.20" host="switch1.local"/>
                <hop ttl="3" ipaddr="10.0.1.100" rtt="4.10"/>
            </trace>
        </host>
    </nmaprun>
    """
    result = parse_nmap_xml(xml)
    host = result.hosts_up[0]

    assert len(host.traceroute) == 3
    assert host.traceroute[0].ip == "10.0.0.1"
    assert host.traceroute[0].hostname == "gateway.local"
    assert host.traceroute[0].ttl == 1
    assert host.traceroute[0].rtt == 1.50


def test_parse_hostscript():
    """Test parsing host-level scripts from <hostscript>."""
    xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
        <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="445">
                    <state state="open"/>
                    <service name="microsoft-ds"/>
                </port>
            </ports>
            <hostscript>
                <script id="smb2-security-mode" output="Message signing enabled but not required"/>
                <script id="smb-os-discovery" output="OS: Windows Server 2019 Standard 17763; Computer name: DC01"/>
                <script id="smb-security-mode" output="account_used: guest; message_signing: disabled"/>
            </hostscript>
        </host>
    </nmaprun>
    """
    result = parse_nmap_xml(xml)
    host = result.hosts_up[0]

    assert len(host.host_scripts) == 3
    assert host.host_scripts[0].script_id == "smb2-security-mode"
    assert "not required" in host.host_scripts[0].output
    assert host.host_scripts[1].script_id == "smb-os-discovery"
    assert "Windows Server 2019" in host.host_scripts[1].output
    assert host.host_scripts[2].script_id == "smb-security-mode"
    assert "disabled" in host.host_scripts[2].output

    # Port-level scripts should be separate
    smb_svc = host.services[0]
    assert len(smb_svc.scripts) == 0  # no port-level scripts in this XML


def test_parse_hostscript_with_port_scripts():
    """Test that host-level and port-level scripts are stored separately."""
    xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
        <host>
            <status state="up"/>
            <address addr="10.0.0.2" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="445">
                    <state state="open"/>
                    <service name="microsoft-ds"/>
                    <script id="smb-os-discovery" output="OS: Windows Server 2019"/>
                </port>
            </ports>
            <hostscript>
                <script id="smb2-security-mode" output="Message signing enabled and required"/>
            </hostscript>
        </host>
    </nmaprun>
    """
    result = parse_nmap_xml(xml)
    host = result.hosts_up[0]

    # Port-level: 1 script on SMB service
    assert len(host.services[0].scripts) == 1
    assert host.services[0].scripts[0].script_id == "smb-os-discovery"

    # Host-level: 1 script
    assert len(host.host_scripts) == 1
    assert host.host_scripts[0].script_id == "smb2-security-mode"


def test_parse_empty_scan():
    """Test parsing a scan with no hosts."""
    xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
        <runstats><finished time="1700000010"/></runstats>
    </nmaprun>
    """
    result = parse_nmap_xml(xml)
    assert len(result.hosts) == 0
    assert result.total_services == 0


def test_parse_invalid_xml_raises():
    """Test that non-Nmap XML raises ValueError."""
    xml = """<?xml version="1.0"?><notNmap><data/></notNmap>"""
    try:
        parse_nmap_xml(xml)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "nmaprun" in str(e)


def test_parse_captures_servicefp():
    """nmap emits the raw probe response in `servicefp` when its built-in
    signatures fail to identify the product. We need that string intact so a
    later analysis pass can extract product hints from it (JSESSIONID,
    Server: headers, characteristic HTML) without re-scanning.
    """
    xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
        <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="8080">
                    <state state="open"/>
                    <service name="http-proxy"
                             servicefp="SF-Port8080-TCP:V=7.92%r(GetRequest,127,&quot;HTTP/1.1 401\\nSet-Cookie: JSESSIONID=ABC&quot;)"/>
                </port>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh" product="OpenSSH" version="8.9"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """
    result = parse_nmap_xml(xml)
    host = result.hosts_up[0]
    http_proxy = next(s for s in host.services if s.port == 8080)
    assert http_proxy.servicefp is not None
    assert "JSESSIONID" in http_proxy.servicefp
    # Services nmap identified confidently carry no servicefp — that's
    # expected nmap behaviour and we should not fabricate one.
    ssh = next(s for s in host.services if s.port == 22)
    assert ssh.servicefp is None


def test_parse_from_file(tmp_path: Path):
    """Test parsing from an actual file path."""
    xml_content = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" start="1700000000" version="7.94">
        <host>
            <status state="up"/>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """
    xml_file = tmp_path / "test_scan.xml"
    xml_file.write_text(xml_content)

    result = parse_nmap_xml(xml_file)
    assert len(result.hosts_up) == 1
    assert result.hosts_up[0].ip == "192.168.1.1"
