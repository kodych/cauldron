"""Tests for rule-based host role classifier."""

from __future__ import annotations

from cauldron.ai.classifier import classify_host, classify_hosts
from cauldron.graph.models import Host, HostRole, Service


def _host(
    ports: list[int],
    products: dict[int, str] | None = None,
    protocol: str = "tcp",
    hostname: str | None = None,
) -> Host:
    """Create a test host with given open ports and optional products.

    Protocol defaults to TCP to match the vast majority of role rules. Pass
    ``protocol='udp'`` to exercise UDP-native service classifications (VPNs,
    SNMP, DNS-only, SIP). Pass ``hostname`` to exercise admin-intent role
    hints from the DNS label.
    """
    services = []
    products = products or {}
    for port in ports:
        svc = Service(port=port, protocol=protocol, state="open", name=None, product=products.get(port))
        services.append(svc)
    return Host(ip="10.0.0.1", hostname=hostname, state="up", services=services)


class TestDomainController:
    def test_full_dc_ports(self):
        host = _host([53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 3389])
        result = classify_host(host)
        assert result.role == HostRole.DOMAIN_CONTROLLER
        assert result.confidence >= 0.90

    def test_minimal_dc(self):
        host = _host([88, 389, 636])
        result = classify_host(host)
        assert result.role == HostRole.DOMAIN_CONTROLLER
        assert result.confidence >= 0.85

    def test_dc_with_kerberos_and_ldap(self):
        host = _host([88, 389, 445])
        result = classify_host(host)
        assert result.role == HostRole.DOMAIN_CONTROLLER

    def test_dc_suppresses_dns_and_file_server(self):
        """DC always has DNS (53) and SMB (445) — should not be classified as DNS/file server."""
        host = _host([53, 88, 135, 389, 445, 636, 3268])
        result = classify_host(host)
        assert result.role == HostRole.DOMAIN_CONTROLLER
        assert HostRole.DNS_SERVER not in result.secondary_roles
        assert HostRole.FILE_SERVER not in result.secondary_roles

    def test_dc_product_keyword_boost(self):
        host = _host([88, 389], {389: "Microsoft Windows Active Directory LDAP"})
        result = classify_host(host)
        assert result.role == HostRole.DOMAIN_CONTROLLER
        assert result.confidence >= 0.85


class TestMailServer:
    def test_exchange_server(self):
        """Real Exchange server with SMTP, POP3, IMAP."""
        host = _host(
            [25, 80, 110, 135, 443, 445, 465, 587, 995],
            {465: "Microsoft Exchange smtpd", 110: "Microsoft Exchange 2007-2010 pop3d"},
        )
        result = classify_host(host)
        assert result.role == HostRole.MAIL_SERVER
        assert result.confidence >= 0.80

    def test_postfix_dovecot(self):
        host = _host([25, 110, 143, 587, 993], {25: "Postfix smtpd", 143: "Dovecot imapd"})
        result = classify_host(host)
        assert result.role == HostRole.MAIL_SERVER
        assert result.confidence >= 0.85

    def test_smtp_only(self):
        host = _host([25, 587])
        result = classify_host(host)
        assert result.role == HostRole.MAIL_SERVER
        assert result.confidence >= 0.70

    def test_mail_suppresses_web(self):
        """Mail servers often have web UI — web should not be primary."""
        host = _host([25, 80, 110, 143, 443, 587])
        result = classify_host(host)
        assert result.role == HostRole.MAIL_SERVER


class TestDatabase:
    def test_mysql(self):
        host = _host([22, 3306], {3306: "MySQL"})
        result = classify_host(host)
        assert result.role == HostRole.DATABASE
        assert result.confidence >= 0.85

    def test_postgresql(self):
        host = _host([22, 5432], {5432: "PostgreSQL"})
        result = classify_host(host)
        assert result.role == HostRole.DATABASE

    def test_mssql(self):
        host = _host([135, 445, 1433, 3389], {1433: "Microsoft SQL Server 2019"})
        result = classify_host(host)
        assert result.role == HostRole.DATABASE
        assert result.confidence >= 0.85

    def test_oracle(self):
        host = _host([22, 1521])
        result = classify_host(host)
        assert result.role == HostRole.DATABASE

    def test_redis(self):
        host = _host([6379])
        result = classify_host(host)
        assert result.role == HostRole.DATABASE


class TestWebServer:
    def test_http_https(self):
        host = _host([80, 443])
        result = classify_host(host)
        assert result.role == HostRole.WEB_SERVER

    def test_apache(self):
        host = _host([80, 443], {80: "Apache httpd"})
        result = classify_host(host)
        assert result.role == HostRole.WEB_SERVER

    def test_nginx(self):
        host = _host([80, 443], {80: "nginx"})
        result = classify_host(host)
        assert result.role == HostRole.WEB_SERVER

    def test_tomcat_alt_ports(self):
        host = _host([8080, 8443], {8080: "Apache Tomcat"})
        result = classify_host(host)
        assert result.role == HostRole.WEB_SERVER

    def test_iis_with_rdp(self):
        """IIS web server that also has RDP — should be web, not remote_access."""
        host = _host([80, 135, 443, 445, 3389], {80: "Microsoft IIS httpd 10.0"})
        result = classify_host(host)
        assert result.role == HostRole.WEB_SERVER


class TestHypervisor:
    def test_vmware_esxi(self):
        host = _host([80, 443, 902, 8000], {443: "VMware ESXi SOAP API", 902: "VMware Authentication Daemon"})
        result = classify_host(host)
        assert result.role == HostRole.HYPERVISOR
        assert result.confidence >= 0.85

    def test_proxmox(self):
        host = _host([22, 8006], {8006: "Proxmox VE"})
        result = classify_host(host)
        assert result.role == HostRole.HYPERVISOR


class TestFileServer:
    def test_nfs(self):
        host = _host([22, 111, 2049])
        result = classify_host(host)
        assert result.role == HostRole.FILE_SERVER
        assert result.confidence >= 0.75

    def test_smb_only_low_confidence(self):
        """SMB alone has low confidence — could be anything Windows."""
        host = _host([135, 139, 445])
        result = classify_host(host)
        # Should classify as file_server but with low confidence
        assert result.confidence <= 0.50


class TestNetworkEquipment:
    def test_snmp_telnet(self):
        host = _host([22, 23, 161], {23: "Cisco router telnetd"})
        result = classify_host(host)
        assert result.role == HostRole.NETWORK_EQUIPMENT
        assert result.confidence >= 0.85

    def test_snmp_only(self):
        host = _host([161])
        result = classify_host(host)
        assert result.role == HostRole.NETWORK_EQUIPMENT


class TestPrinter:
    def test_full_printer(self):
        host = _host([80, 515, 631, 9100])
        result = classify_host(host)
        assert result.role == HostRole.PRINTER
        assert result.confidence >= 0.90

    def test_jetdirect_only(self):
        host = _host([9100])
        result = classify_host(host)
        assert result.role == HostRole.PRINTER


class TestVoIP:
    def test_asterisk(self):
        host = _host([22, 5060, 5061], {5060: "Asterisk PBX"})
        result = classify_host(host)
        assert result.role == HostRole.VOIP
        assert result.confidence >= 0.90

    def test_sip_only(self):
        host = _host([5060])
        result = classify_host(host)
        assert result.role == HostRole.VOIP


class TestSIEM:
    def test_splunk_ports(self):
        host = _host([8000, 8089])
        result = classify_host(host)
        assert result.role == HostRole.SIEM
        assert result.confidence >= 0.85

    def test_elk_stack(self):
        host = _host([9200, 5601])
        result = classify_host(host)
        assert result.role == HostRole.SIEM
        assert result.confidence >= 0.80

    def test_wazuh_product(self):
        host = _host([1514, 1515], {1514: "Wazuh manager"})
        result = classify_host(host)
        assert result.role == HostRole.SIEM

    def test_syslog_alone_low_confidence(self):
        host = _host([514])
        result = classify_host(host)
        assert result.role == HostRole.SIEM
        assert result.confidence <= 0.70


class TestCICD:
    def test_jenkins_ports(self):
        host = _host([8080, 50000])
        result = classify_host(host)
        assert result.role == HostRole.CI_CD
        assert result.confidence >= 0.80

    def test_jenkins_product_with_agent_port(self):
        host = _host([8080, 50000], {8080: "Jenkins"})
        result = classify_host(host)
        assert result.role == HostRole.CI_CD

    def test_ci_cd_suppresses_web(self):
        """CI/CD with high confidence should suppress web_server."""
        host = _host([8080, 50000])
        result = classify_host(host)
        assert result.role == HostRole.CI_CD
        assert HostRole.WEB_SERVER not in result.secondary_roles


class TestVPNGateway:
    def test_openvpn(self):
        host = _host([1194])
        result = classify_host(host)
        assert result.role == HostRole.VPN_GATEWAY
        assert result.confidence >= 0.80

    def test_ipsec(self):
        host = _host([500, 4500])
        result = classify_host(host)
        assert result.role == HostRole.VPN_GATEWAY
        assert result.confidence >= 0.85

    def test_wireguard_product(self):
        host = _host([51820], {51820: "WireGuard"})
        result = classify_host(host)
        assert result.role == HostRole.VPN_GATEWAY

    def test_vpn_suppresses_remote_access(self):
        host = _host([1194, 3389])
        result = classify_host(host)
        assert result.role == HostRole.VPN_GATEWAY
        assert HostRole.REMOTE_ACCESS not in result.secondary_roles


class TestBackup:
    def test_bacula_ports(self):
        host = _host([9102, 9103])
        result = classify_host(host)
        assert result.role == HostRole.BACKUP
        assert result.confidence >= 0.75

    def test_veeam_product(self):
        host = _host([9392], {9392: "Veeam Backup"})
        result = classify_host(host)
        assert result.role == HostRole.BACKUP


class TestEdgeCases:
    def test_no_open_ports(self):
        host = _host([])
        result = classify_host(host)
        assert result.role == HostRole.UNKNOWN
        assert result.confidence == 0.0

    def test_single_ssh_port(self):
        """SSH only — not enough to classify."""
        host = _host([22])
        result = classify_host(host)
        assert result.role == HostRole.UNKNOWN

    def test_rdp_only_low_confidence(self):
        """RDP only — should be remote_access with very low confidence."""
        host = _host([3389])
        result = classify_host(host)
        assert result.role == HostRole.REMOTE_ACCESS
        assert result.confidence <= 0.40

    def test_classify_hosts_batch(self):
        """Test batch classification updates host objects."""
        hosts = [
            _host([88, 389, 636, 3268]),
            _host([80, 443]),
            _host([3306]),
        ]
        classify_hosts(hosts)
        assert hosts[0].role == HostRole.DOMAIN_CONTROLLER
        assert hosts[1].role == HostRole.WEB_SERVER
        assert hosts[2].role == HostRole.DATABASE


class TestUdpOnlyHosts:
    """Regression: hosts exposing only UDP services must still classify.

    The earlier classifier filtered down to TCP ports before matching, so
    every UDP-native service class (WireGuard, OpenVPN, IPSec, pure-UDP DNS,
    SNMP-only network gear, SIP VoIP) silently fell into ``unknown``.
    """

    def test_wireguard_udp_only(self):
        host = _host([51820], protocol="udp")
        result = classify_host(host)
        assert result.role == HostRole.VPN_GATEWAY

    def test_ipsec_udp_only(self):
        host = _host([500, 4500], protocol="udp")
        result = classify_host(host)
        assert result.role == HostRole.VPN_GATEWAY

    def test_openvpn_udp_only(self):
        host = _host([1194], protocol="udp")
        result = classify_host(host)
        assert result.role == HostRole.VPN_GATEWAY

    def test_snmp_udp_only(self):
        host = _host([161], protocol="udp")
        result = classify_host(host)
        assert result.role == HostRole.NETWORK_EQUIPMENT

    def test_sip_udp_only(self):
        host = _host([5060], protocol="udp")
        result = classify_host(host)
        assert result.role == HostRole.VOIP

    def test_dns_udp_only(self):
        host = _host([53], protocol="udp")
        result = classify_host(host)
        assert result.role == HostRole.DNS_SERVER

    def test_windows_server_generic(self):
        """Generic Windows server with just RPC + SMB + RDP."""
        host = _host([135, 139, 445, 3389])
        result = classify_host(host)
        # Should pick something, not stay unknown
        assert result.role in (HostRole.FILE_SERVER, HostRole.REMOTE_ACCESS)


class TestManagement:
    """Test MANAGEMENT role detection (WSUS, SCCM/MECM)."""

    def test_wsus_server(self):
        host = _host([80, 8530, 8531, 135, 445, 3389])
        result = classify_host(host)
        assert result.role == HostRole.MANAGEMENT

    def test_sccm_server(self):
        host = _host([80, 443, 2701, 135, 445, 3389])
        result = classify_host(host)
        assert result.role == HostRole.MANAGEMENT

    def test_sccm_wsus_combo(self):
        host = _host([80, 443, 2701, 8530, 8531, 135, 445, 3389])
        result = classify_host(host)
        assert result.role == HostRole.MANAGEMENT
        assert result.confidence >= 0.90

    def test_management_suppresses_web(self):
        host = _host([80, 443, 8530, 8531, 135, 445])
        result = classify_host(host)
        assert result.role == HostRole.MANAGEMENT
        assert HostRole.WEB_SERVER not in result.secondary_roles

    def test_management_product_keyword(self):
        host = _host([80, 443, 8530], products={80: "Microsoft WSUS"})
        result = classify_host(host)
        assert result.role == HostRole.MANAGEMENT


class TestBackupImproved:
    """Test BACKUP role improvements."""

    def test_backup_exec_keyword(self):
        host = _host([10000, 135, 445], products={10000: "Symantec Backup Exec ndmp"})
        result = classify_host(host)
        assert result.role == HostRole.BACKUP

    def test_storagecraft_keyword(self):
        host = _host([9392, 135, 445], products={9392: "StorageCraft Image Manager"})
        result = classify_host(host)
        assert result.role == HostRole.BACKUP

    def test_ndmp_keyword(self):
        host = _host([10000, 135, 445], products={10000: "ndmp"})
        result = classify_host(host)
        assert result.role == HostRole.BACKUP

    def test_nfs_plus_ndmp(self):
        host = _host([111, 2049, 10000, 135, 445])
        result = classify_host(host)
        assert result.role == HostRole.BACKUP

    def test_backup_suppresses_file_server(self):
        host = _host([111, 2049, 10000, 135, 445], products={10000: "Veritas Backup Exec"})
        result = classify_host(host)
        assert result.role == HostRole.BACKUP
        assert HostRole.FILE_SERVER not in result.secondary_roles


class TestHostnameSignals:
    """Hostname is admin intent — the strongest single signal of role.

    Earlier the classifier only looked at open ports + banners, so a host
    named ``dc01.corp.local`` whose Kerberos/LDAP ports were filtered fell
    into ``unknown`` with nothing to go on. Hostname token matching gives
    that class of host a 0.70 floor (equivalent to a minimal port match).
    """

    def test_filtered_dc_classifies_from_hostname(self):
        host = _host([], hostname="dc01.corp.local")
        result = classify_host(host)
        assert result.role == HostRole.DOMAIN_CONTROLLER
        assert result.confidence >= 0.70

    def test_mail_hostname_alone(self):
        host = _host([], hostname="mail-prod.example.com")
        result = classify_host(host)
        assert result.role == HostRole.MAIL_SERVER

    def test_database_hostname_alone(self):
        host = _host([], hostname="sqlsrv01.corp.local")
        result = classify_host(host)
        assert result.role == HostRole.DATABASE

    def test_vcenter_hostname_alone(self):
        host = _host([], hostname="vcenter.corp.local")
        result = classify_host(host)
        assert result.role == HostRole.HYPERVISOR

    def test_wireguard_hostname_alone(self):
        host = _host([], hostname="wg01.example.com")
        result = classify_host(host)
        assert result.role == HostRole.VPN_GATEWAY

    def test_ns_matches_dns(self):
        host = _host([], hostname="ns01.corp.local")
        result = classify_host(host)
        assert result.role == HostRole.DNS_SERVER

    def test_nsg_does_not_match_dns(self):
        """Azure NSG (``nsg01``) must not collide with DNS token ``ns``.

        Tokenisation yields {'nsg'}, not {'ns', 'g'} — exact set
        intersection keeps this boundary crisp without regex gymnastics.
        """
        host = _host([], hostname="nsg01.example.local")
        result = classify_host(host)
        assert result.role == HostRole.UNKNOWN

    def test_hostname_does_not_override_strong_port_evidence(self):
        """Host named ``dc01`` but actually serving nginx web stack.

        Strong port+banner match (web_server ~0.85 after banner boost)
        beats the hostname baseline of 0.70 — a mis-named host still gets
        the role its ports prove, not the role its name claims.
        """
        host = _host(
            [80, 443],
            products={80: "nginx", 443: "nginx"},
            hostname="dc01.example.local",
        )
        result = classify_host(host)
        assert result.role == HostRole.WEB_SERVER

    def test_hostname_lifts_partial_port_match(self):
        """Database on a non-standard port + ``sql01`` hostname.

        Port match alone is weak (MySQL on 3306 gives 0.85; without it,
        we have nothing). Hostname tips the classification.
        """
        host = _host([], hostname="sql01-prod.corp.local")
        result = classify_host(host)
        assert result.role == HostRole.DATABASE

    def test_hostname_with_matching_ports_confirms(self):
        """Ports + hostname align — port evidence keeps winning, hostname
        does not downgrade it."""
        host = _host([88, 389, 636, 3268], hostname="dc01.corp.local")
        result = classify_host(host)
        assert result.role == HostRole.DOMAIN_CONTROLLER
        assert result.confidence >= 0.90  # ports give 0.95, hostname is a no-op here

    def test_no_ports_no_hostname_is_unknown(self):
        host = _host([], hostname=None)
        result = classify_host(host)
        assert result.role == HostRole.UNKNOWN
        assert result.confidence == 0.0

    def test_unrecognized_hostname_falls_through(self):
        """Hostname with no role-hint tokens → same as no hostname."""
        host = _host([], hostname="appserver42.internal")
        result = classify_host(host)
        assert result.role == HostRole.UNKNOWN
