/**
 * CYBER ATTACK BOOK - FOSS DETECTION & DEFENSE TOOLS REPOSITORY
 * Comprehensive catalog of Free & Open-Source Software (FOSS) security tools,
 * detection engines, HIDS/NIDS, WAFs, and forensic frameworks mapped to threat vectors.
 */

const FOSS_TOOLS_DATA = [
  // =========================================================================
  // 1. NETWORK INTRUSION DETECTION & PACKET INSPECTION
  // =========================================================================
  {
    id: "suricata",
    name: "Suricata",
    category: "network",
    categoryLabel: "Network IDS / IPS",
    license: "GPLv2",
    website: "https://suricata.io",
    summary: "High-performance, multi-threaded Network Threat Detection, IDS, IPS, and Network Security Monitoring (NSM) engine developed by the Open Information Security Foundation (OISF). Capable of multi-gigabit wire-speed traffic inspection.",
    detectionRole: "Performs real-time deep packet inspection (DPI), protocol parsing (HTTP/1/2, TLS, DNS, SMB, SSH), flow tracking, file extraction, and JA3/JA4 TLS fingerprinting. Generates structured JSON telemetry (Eve.json) for SIEM ingestion.",
    defenseRole: "When deployed inline (via NFQueue, AF_PACKET, or DPDK bypass), actively blocks malicious connections, drops malicious TCP/UDP packets, resets TCP connections, and isolates compromised subnets.",
    ruleFormat: "Suricata Rules",
    sampleRule: `# Suricata Rule: Detect and Drop SSRF Exfiltration to Cloud Metadata Service
drop http $HOME_NET any -> any any (
    msg:"SEC-FOSS-SURICATA Outbound Cloud Metadata Credential Theft (SSRF)";
    flow:established,to_server;
    content:"169.254.169.254"; http_uri;
    content:"/latest/meta-data/"; http_uri;
    classtype:web-application-attack;
    sid:2026101;
    rev:1;
)`,
    linkedAttacks: [
      { num: 1, id: "dos", name: "Denial-of-Service (DoS)" },
      { num: 2, id: "ddos", name: "Distributed Denial-of-Service (DDoS)" },
      { num: 3, id: "mitm", name: "Man-in-the-Middle (MitM)" },
      { num: 4, id: "dns-spoofing", name: "DNS Spoofing" },
      { num: 5, id: "port-scanning", name: "Port Scanning" },
      { num: 11, id: "sql-injection", name: "SQL Injection" },
      { num: 14, id: "ssrf", name: "Server-Side Request Forgery" },
      { num: 15, id: "rce", name: "Remote Code Execution" },
      { num: 73, id: "ssh-bruteforce", name: "SSH Brute-Force" },
      { num: 93, id: "ssrf-attack", name: "OWASP SSRF" },
      { num: 94, id: "http-request-smuggling", name: "HTTP Request Smuggling" },
      { num: 99, id: "command-injection", name: "Command Injection" }
    ]
  },
  {
    id: "snort3",
    name: "Snort 3",
    category: "network",
    categoryLabel: "Network IDS / IPS",
    license: "GPLv2",
    website: "https://www.snort.org",
    summary: "Next-generation open-source packet inspection and network intrusion prevention system. Redesigned with a modular multi-threaded architecture, Lua-based rule configuration, and high-throughput buffer inspection.",
    detectionRole: "Evaluates raw packet streams against thousands of rule headers and payload regexes. Performs deep protocol decodes, TCP flow tracking, and cross-packet stream normalizations to uncover obfuscated exploits.",
    defenseRole: "Hardware bypass inline filtering with direct packet discard (`drop`, `reject`, `sdrop`), dynamic stream termination, and immediate perimeter firewall trigger integration.",
    ruleFormat: "Snort 3 Lua Rule",
    sampleRule: `-- Snort 3 Rule: Detect Exploit Payload Shellcode NOP Sled
ips = {
    rules = [[
        reject tcp $EXTERNAL_NET any -> $HOME_NET 21 (
            msg:"SEC-FOSS-SNORT3 FTP Inbound Buffer Overflow NOP Sled";
            flow:to_server,established;
            content:"|90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90|",fast_pattern;
            classtype:attempted-admin;
            sid:1000045;
            rev:2;
        )
    ]]
}`,
    linkedAttacks: [
      { num: 1, id: "dos", name: "Denial-of-Service" },
      { num: 5, id: "port-scanning", name: "Port Scanning" },
      { num: 6, id: "buffer-overflow", name: "Buffer Overflow" },
      { num: 73, id: "ssh-bruteforce", name: "SSH Brute-Force" },
      { num: 80, id: "spec-buffer-overflow", name: "Specialized Buffer Overflow" }
    ]
  },
  {
    id: "zeek",
    name: "Zeek (formerly Bro)",
    category: "network",
    categoryLabel: "Network Security Monitoring",
    license: "BSD-3-Clause",
    website: "https://zeek.org",
    summary: "Domain-specific network security monitoring and behavioral traffic analysis framework. Unlike signature matching engines, Zeek converts high-volume raw packet streams into compact, structured behavioral logs.",
    detectionRole: "Maintains protocol state machines across hundreds of application protocols. Generates comprehensive audit logs (conn.log, http.log, dns.log, ssl.log, kerberos.log) that reveal C2 beaconing, SMB lateral movement, and data exfiltration.",
    defenseRole: "Integrates with SDN controllers and firewalls via Zeek script actions to automatically shunt anomalous IP connections, blackhole compromised domain lookups, and invoke SOAR webhooks.",
    ruleFormat: "Zeek Policy Script",
    sampleRule: `# Zeek Script: Detect Kerberoasting via RC4 Ticket Request Spikes
event kerberos_tgs_request(c: connection, msg: Kerberos::TGS_REQ) {
    if (msg?$enctype && msg$enctype == 23) { # 23 = RC4-HMAC
        NOTICE([$note=Kerberos::Weak_Cipher_TGS,
                $msg=fmt("Kerberoasting RC4 SPN Ticket Request from %s to %s", c$id$orig_h, msg$service),
                $conn=c]);
    }
}`,
    linkedAttacks: [
      { num: 3, id: "mitm", name: "Man-in-the-Middle" },
      { num: 4, id: "dns-spoofing", name: "DNS Spoofing" },
      { num: 34, id: "password-spraying", name: "Password Spraying" },
      { num: 68, id: "pass-the-hash", name: "Pass-the-Hash" },
      { num: 69, id: "kerberoasting", name: "Kerberoasting" },
      { num: 105, id: "automated-scraping", name: "Automated DB Scraping" }
    ]
  },
  {
    id: "wireshark",
    name: "Wireshark / TShark",
    category: "network",
    categoryLabel: "Packet Analyzer & Forensics",
    license: "GPLv2",
    website: "https://www.wireshark.org",
    summary: "The world's foremost network protocol analyzer and deep packet dissection toolkit. Used by SOC forensic analysts to inspect micro-level packet exchanges, protocol anomalies, and unencrypted credentials.",
    detectionRole: "Live and offline packet capture inspection with support for thousands of protocols. Decrypts TLS session keys (SSLKEYLOGFILE), flags protocol standard violations, detects abnormal ARP responses and rogue DHCP leases.",
    defenseRole: "Serves as the core diagnostic verification tool to validate firewall efficacy, reconstruct exfiltrated artifacts, and build precise PCAP signatures for IDS/IPS deployment.",
    ruleFormat: "Wireshark Display Filter",
    sampleRule: `# Filter ARP poisoning & Duplicate IP claims (MitM Detection)
(arp.opcode == 2) && (arp.duplicate-address-frame || arp.isgratuitous == 1)`,
    linkedAttacks: [
      { num: 3, id: "mitm", name: "Man-in-the-Middle" },
      { num: 4, id: "dns-spoofing", name: "DNS Spoofing" },
      { num: 40, id: "evil-twin", name: "Evil Twin" },
      { num: 42, id: "deauth-attack", name: "Deauthentication Attack" },
      { num: 50, id: "arp-spoofing", name: "ARP Spoofing" },
      { num: 53, id: "dhcp-starvation", name: "DHCP Starvation" }
    ]
  },
  {
    id: "arpwatch",
    name: "Arpwatch",
    category: "network",
    categoryLabel: "Layer 2 Ethernet Monitor",
    license: "BSD-4-Clause",
    website: "https://ee.lbl.gov",
    summary: "Computer security tool for monitoring Address Resolution Protocol (ARP) traffic on an Ethernet LAN. Detects MAC address changes, flip-flops, and rogue host claims on local broadcast domains.",
    detectionRole: "Maintains a persistent database of Ethernet MAC-to-IP pairings. Logs real-time syslog alerts whenever an IP address transitions to a different hardware MAC address or unknown Ethernet vendors appear.",
    defenseRole: "Provides immediate notification of ARP spoofing and MAC flooding attacks, enabling SOC engineers to disable compromised switch ports via 802.1X or port-security automation.",
    ruleFormat: "Arpwatch Syslog Pattern",
    sampleRule: `# Detects ARP Cache Poisoning / MAC Flip-Flop
arpwatch: flip flop 192.168.1.50 00:0c:29:ab:cd:ef (00:50:56:12:34:56)`,
    linkedAttacks: [
      { num: 3, id: "mitm", name: "Man-in-the-Middle" },
      { num: 50, id: "arp-spoofing", name: "ARP Spoofing" },
      { num: 51, id: "mac-flooding", name: "MAC Flooding" }
    ]
  },

  // =========================================================================
  // 2. ENDPOINT DETECTION, HIDS & HOST RUNTIME
  // =========================================================================
  {
    id: "wazuh",
    name: "Wazuh",
    category: "host",
    categoryLabel: "Host XDR & EDR Platform",
    license: "GPLv2",
    website: "https://wazuh.com",
    summary: "Open-source enterprise Extended Detection and Response (XDR) and Security Information and Event Management (SIEM) platform. Deploys lightweight cross-platform agents across Windows, Linux, and macOS.",
    detectionRole: "Real-time log analysis, File Integrity Monitoring (FIM / Syscheck), rootkit scanning, vulnerability assessment, Windows Event Log / Sysmon integration, and compliance policy auditing (CIS, PCI-DSS, NIST).",
    defenseRole: "Executes automated Active Response scripts upon threat detection: isolates host from the network, terminates offending process IDs (PIDs), wipes active attacker user sessions, and adds firewall blocks.",
    ruleFormat: "Wazuh XML Rule",
    sampleRule: `<!-- Wazuh Rule: Detect Ransomware Deleting Windows Shadow Copies -->
<group name="windows,ransomware_defense,">
  <rule id="100340" level="12">
    <if_sid>60103</if_sid>
    <field name="win.eventdata.image">vssadmin.exe</field>
    <match>delete shadows</match>
    <description>CRITICAL: Ransomware Shadow Copy Invalidation Attempt Detected</description>
    <mitre><id>T1490</id></mitre>
  </rule>
</group>`,
    linkedAttacks: [
      { num: 1, id: "dos", name: "Denial-of-Service" },
      { num: 7, id: "priv-escalation", name: "Privilege Escalation" },
      { num: 8, id: "rootkit", name: "Rootkit" },
      { num: 9, id: "dll-hijacking", name: "DLL Hijacking" },
      { num: 65, id: "null-session", name: "Null Session Attack" },
      { num: 67, id: "win-priv-esc", name: "Windows Priv Escalation" },
      { num: 71, id: "linux-rootkit", name: "Linux Kernel Rootkit" },
      { num: 72, id: "linux-priv-esc", name: "Linux Privilege Escalation" },
      { num: 74, id: "suid-exploitation", name: "SUID Exploitation" },
      { num: 108, id: "data-destruction", name: "Data Destruction & Wipers" }
    ]
  },
  {
    id: "falco",
    name: "Falco",
    category: "host",
    categoryLabel: "Cloud-Native Runtime Security",
    license: "Apache 2.0 (CNCF)",
    website: "https://falco.org",
    summary: "The open-source standard for continuous risk and threat detection across Kubernetes, containers, and Linux hosts. Intercepts system calls directly at the kernel boundary via modern eBPF probes.",
    detectionRole: "Analyzes system calls (execve, openat, socket, ptrace) to detect container escapes, unexpected reverse shell execution, root namespace traversal, sensitive file tampering (`/etc/shadow`, `/proc`), and SUID misuse.",
    defenseRole: "Integrates with Falco Sidekick to trigger automated response playbooks: immediately terminates the compromised pod, cordons the Kubernetes node, revokes cloud IAM credentials, and pauses namespaces.",
    ruleFormat: "Falco YAML Rule",
    sampleRule: `# Falco Rule: Detect Shell Execution Inside Web App Container
- rule: Shell Spawned in Web Container
  desc: Detects an interactive shell spawned by an untrusted web process
  condition: >
    container.id != host and
    proc.name in (bash, sh, zsh) and
    proc.pname in (nginx, apache2, httpd, node, python, java)
  output: >
    CRITICAL Reverse Shell in Container (pod=%k8s.pod.name proc=%proc.name parent=%proc.pname cmd=%proc.cmdline)
  priority: CRITICAL
  tags: [container, mitre_execution, T1059]`,
    linkedAttacks: [
      { num: 7, id: "priv-escalation", name: "Privilege Escalation" },
      { num: 15, id: "rce", name: "Remote Code Execution" },
      { num: 72, id: "linux-priv-esc", name: "Linux Privilege Escalation" },
      { num: 74, id: "suid-exploitation", name: "SUID Exploitation" },
      { num: 82, id: "race-condition", name: "Race Condition Attack" },
      { num: 88, id: "security-misconfiguration", name: "Security Misconfiguration" },
      { num: 99, id: "command-injection", name: "Command Injection" }
    ]
  },
  {
    id: "auditd",
    name: "Auditd & Go-Audit",
    category: "host",
    categoryLabel: "Kernel Syscall Auditing",
    license: "GPLv2",
    website: "https://github.com/linux-audit/audit-userspace",
    summary: "The native Linux Audit Daemon subsystem. Resides directly inside the Linux kernel to log security-relevant system calls, file permissions changes, and administrative identity switches.",
    detectionRole: "Tracks every execution of `execve`, changes to critical directories (`/etc/`, `/var/log/`), unauthorized SUID binary runs, module insertions (`init_module`), and privilege escalations (`setuid`).",
    defenseRole: "Generates tamper-resistant, immutable audit trails. When configured with audit rules, feeds local HIDS agents to immediately revoke compromised sessions or trip emergency host isolation.",
    ruleFormat: "Auditd Rule (.rules)",
    sampleRule: `# Auditd Rules: Monitor SUID Priv Escalation and Password File Access
-w /etc/shadow -p wa -k identity_tampering
-w /etc/sudoers -p wa -k sudoers_modification
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k suid_execution`,
    linkedAttacks: [
      { num: 70, id: "linux-nfs", name: "Linux NFS Attack" },
      { num: 71, id: "linux-rootkit", name: "Linux Kernel Rootkit" },
      { num: 72, id: "linux-priv-esc", name: "Linux Privilege Escalation" },
      { num: 74, id: "suid-exploitation", name: "SUID Exploitation" },
      { num: 82, id: "race-condition", name: "Race Condition Attack" }
    ]
  },
  {
    id: "osquery",
    name: "osquery",
    category: "host",
    categoryLabel: "SQL-Powered Host Telemetry",
    license: "Apache 2.0",
    website: "https://osquery.io",
    summary: "Operating system instrumentation framework created by Facebook. Exposes an operating system (Windows, Linux, macOS) as a high-performance relational database queryable via standard SQL syntax.",
    detectionRole: "Allows SOC teams and EDR managers to query listening sockets, running processes, kernel extensions, unquoted service paths, cron persistence, browser extensions, and logged-in user activity.",
    defenseRole: "Executes continuous scheduled queries (`osqueryd`) that output diff-results directly to SIEM pipelines, detecting host configuration drift, missing patches, and unauthorized administrative backdoors.",
    ruleFormat: "osquery SQL Query",
    sampleRule: `-- osquery: Detect Unquoted Windows Service Paths (Privilege Escalation Vector)
SELECT name, display_name, path, user_account 
FROM services 
WHERE path NOT LIKE '"%' 
  AND path LIKE '%.exe%' 
  AND path LIKE '% %' 
  AND start_type = 'AUTO_START';`,
    linkedAttacks: [
      { num: 9, id: "dll-hijacking", name: "DLL Hijacking" },
      { num: 66, id: "missing-patch", name: "Missing Patch Exploitation" },
      { num: 67, id: "win-priv-esc", name: "Windows Priv Escalation" },
      { num: 75, id: "macos-priv-esc", name: "macOS Privilege Escalation" },
      { num: 78, id: "gatekeeper-bypass", name: "Gatekeeper Bypass" },
      { num: 79, id: "launch-daemon", name: "Launch Agent/Daemon Abuse" }
    ]
  },
  {
    id: "velociraptor",
    name: "Velociraptor",
    category: "host",
    categoryLabel: "Endpoint Forensics & Hunting",
    license: "AGPLv3",
    website: "https://docs.velociraptor.app",
    summary: "Advanced digital forensics and incident response (DFIR) endpoint hunting platform. Uses the proprietary Velociraptor Query Language (VQL) to inspect thousands of enterprise endpoints in seconds.",
    detectionRole: "Hunts for in-memory payloads, Master File Table ($MFT) anomalies, Windows Prefetch and Amcache execution artifacts, scheduled task persistence, and LSASS credential dumping signatures.",
    defenseRole: "Enables instant live host triage: isolates compromised endpoints from the LAN, dumps volatile memory dumps for offline analysis, and terminates rogue malicious executables remotely.",
    ruleFormat: "Velociraptor VQL Script",
    sampleRule: `// VQL: Hunt for Persistence via Rogue Scheduled Tasks
SELECT Name, Command, Arguments, Enabled 
FROM Artifact.Windows.System.TaskScheduler()
WHERE Command =~ 'powershell|cmd|wscript|cscript' 
  AND Arguments =~ 'EncodedCommand|bypass|hidden'`,
    linkedAttacks: [
      { num: 35, id: "offline-cracking", name: "Offline Password Cracking" },
      { num: 67, id: "win-priv-esc", name: "Windows Priv Escalation" },
      { num: 68, id: "pass-the-hash", name: "Pass-the-Hash" },
      { num: 79, id: "launch-daemon", name: "Launch Agent Abuse" },
      { num: 108, id: "data-destruction", name: "Data Destruction" }
    ]
  },

  // =========================================================================
  // 3. WEB APPLICATION FIREWALLS (WAF) & REVERSE PROXIES
  // =========================================================================
  {
    id: "modsecurity",
    name: "ModSecurity & Coraza WAF",
    category: "web",
    categoryLabel: "Web App Firewall (WAF)",
    license: "Apache 2.0",
    website: "https://coraza.io",
    summary: "Industry-standard open-source Web Application Firewall (WAF) engines. ModSecurity and its modern Go-based successor Coraza embed seamlessly into Nginx, Apache, Envoy, and Traefik reverse proxies.",
    detectionRole: "Deep inspection of incoming HTTP request parameters, URI query strings, request headers, cookies, JSON, XML, and multipart file uploads against the OWASP Core Rule Set (CRS).",
    defenseRole: "Blocks malicious L7 requests in real time (HTTP 403 Forbidden), strips sensitive headers from backend responses (preventing information disclosure), and enforces sliding-window rate limits.",
    ruleFormat: "SecRule / OWASP CRS Directive",
    sampleRule: `# ModSecurity Rule: Block SQL Injection in URL or POST Body
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "@rx (?i)(?:(?:union\\s+(?:all\\s+)?select)|(?:select\\s+.*\\s+from))" \\
    "id:942100,\\
    phase:2,\\
    block,\\
    capture,\\
    t:none,t:urlDecodeUni,t:lowercase,\\
    msg:'SQL Injection Attempt Blocked by OWASP CRS',\\
    tag:'attack-sqli',\\
    setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"`,
    linkedAttacks: [
      { num: 11, id: "sql-injection", name: "SQL Injection" },
      { num: 12, id: "xss", name: "Cross-Site Scripting" },
      { num: 13, id: "csrf", name: "Cross-Site Request Forgery" },
      { num: 14, id: "ssrf", name: "Server-Side Request Forgery" },
      { num: 84, id: "broken-access-control", name: "Broken Access Control" },
      { num: 86, id: "owasp-injection", name: "OWASP Injection" },
      { num: 93, id: "ssrf-attack", name: "OWASP SSRF" },
      { num: 94, id: "http-request-smuggling", name: "HTTP Request Smuggling" },
      { num: 98, id: "directory-traversal", name: "Directory Traversal" },
      { num: 100, id: "xxe-injection", name: "XML External Entity" },
      { num: 101, id: "blind-sql-injection", name: "Blind SQL Injection" }
    ]
  },
  {
    id: "fail2ban",
    name: "Fail2ban & CrowdSec",
    category: "web",
    categoryLabel: "Log-Based IPS & IP Jailing",
    license: "GPLv2 / MIT",
    website: "https://crowdsec.net",
    summary: "Automated intrusion prevention software. Fail2ban parses authentication and web daemon logs to execute dynamic firewall bans. CrowdSec extends this with a global, crowdsourced cyber threat intelligence consensus.",
    detectionRole: "Identifies repeated authentication failures, aggressive directory fuzzing (404/403 floods), SSH password brute-forcing, and credential stuffing patterns in real-time server log streams.",
    defenseRole: "Updates kernel packet filtering tables (`nftables`, `iptables`, `pf`, or AWS Security Groups) to drop all packets from attacker IPs for a configurable quarantine period (e.g., 24 hours to permanent).",
    ruleFormat: "Fail2ban Jail (.local)",
    sampleRule: `# /etc/fail2ban/jail.local: Auto-Jail SSH & Web Authentication Attacks
[sshd]
enabled   = true
port      = ssh
filter    = sshd
logpath   = /var/log/auth.log
maxretry  = 3
findtime  = 300
bantime   = 86400
banaction = nftables-multiport`,
    linkedAttacks: [
      { num: 1, id: "dos", name: "Denial-of-Service" },
      { num: 31, id: "brute-force", name: "Brute-Force Attack" },
      { num: 32, id: "dictionary-attack", name: "Dictionary Attack" },
      { num: 33, id: "credential-stuffing", name: "Credential Stuffing" },
      { num: 34, id: "password-spraying", name: "Password Spraying" },
      { num: 73, id: "ssh-bruteforce", name: "SSH Brute-Force" },
      { num: 98, id: "directory-traversal", name: "Directory Traversal" }
    ]
  },

  // =========================================================================
  // 4. SIEM, LOG AGGREGATION & DETECTION ENGINEERING
  // =========================================================================
  {
    id: "sigma",
    name: "Sigma",
    category: "siem",
    categoryLabel: "SIEM Detection Rule Standard",
    license: "DRL 1.1",
    website: "https://github.com/SigmaHQ/sigma",
    summary: "Generic, open, vendor-agnostic signature format for log detection engineering. Allows cyber defenders to describe log patterns once and convert them into Splunk SPL, Elastic DSL, Microsoft Sentinel KQL, or QRadar AQL.",
    detectionRole: "Defines precise Boolean logic matching process creations, registry tweaks, network flows, and credential dumping events across Sysmon, Windows Security logs, Linux auditd, and AWS CloudTrail.",
    defenseRole: "Standardizes SOC threat hunting workflows, automates CI/CD detection engineering pipelines, and eliminates vendor lock-in across SIEM architectures.",
    ruleFormat: "Sigma YAML Rule",
    sampleRule: `title: Pass-the-Hash / NTLM Logon with Empty Key
id: 5698b7f8-b3d9-4820-b467-33a7d4c89df2
status: production
description: Detects lateral movement via Pass-the-Hash using NTLM authentication
logsource:
    category: logon
    product: windows
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
        LmPackageName: 'NTLM V1'
    condition: selection
level: high
tags:
    - attack.lateral_movement
    - attack.t1550.002`,
    linkedAttacks: [
      { num: 1, id: "dos", name: "Denial-of-Service" },
      { num: 35, id: "offline-cracking", name: "Offline Password Cracking" },
      { num: 66, id: "missing-patch", name: "Missing Patch Exploitation" },
      { num: 67, id: "win-priv-esc", name: "Windows Priv Escalation" },
      { num: 68, id: "pass-the-hash", name: "Pass-the-Hash" },
      { num: 69, id: "kerberoasting", name: "Kerberoasting" },
      { num: 79, id: "launch-daemon", name: "Launch Daemon Abuse" },
      { num: 108, id: "data-destruction", name: "Data Destruction" }
    ]
  },
  {
    id: "opensearch",
    name: "OpenSearch & ELK Stack",
    category: "siem",
    categoryLabel: "Enterprise Log Analytics / SIEM",
    license: "Apache 2.0 (OpenSearch)",
    website: "https://opensearch.org",
    summary: "Scalable open-source search, log analytics, and threat visualization platform. Ingests petabytes of operational telemetry and security events to power modern enterprise Security Operations Centers (SOC).",
    detectionRole: "Indexes structured events from firewalls, servers, WAFs, and endpoints. Executes real-time anomaly detection detectors, cross-cluster correlations, and automated threshold alerts.",
    defenseRole: "Triggers automated webhook integrations to Slack, PagerDuty, or SOAR runbooks to orchestrate firewall blocklisting, ticket dispatching, and automated host isolation.",
    ruleFormat: "OpenSearch Alert Monitor (DSL)",
    sampleRule: `{
  "name": "Surge in HTTP 500/503 Errors (DDoS / L7 Flooding)",
  "type": "monitor",
  "schedule": { "period": { "interval": 1, "unit": "MINUTES" } },
  "inputs": [{
    "search": {
      "indices": ["nginx-access-*"],
      "query": {
        "range": { "status": { "gte": 500 } }
      }
    }
  }]
}`,
    linkedAttacks: [
      { num: 1, id: "dos", name: "Denial-of-Service" },
      { num: 2, id: "ddos", name: "Distributed Denial-of-Service" },
      { num: 33, id: "credential-stuffing", name: "Credential Stuffing" },
      { num: 34, id: "password-spraying", name: "Password Spraying" },
      { num: 92, id: "logging-failures", name: "Security Logging Failures" },
      { num: 106, id: "s3-exposure", name: "S3 Bucket Exposure" }
    ]
  },

  // =========================================================================
  // 5. MALWARE SCANNING, ARTIFACTS & MEMORY FORENSICS
  // =========================================================================
  {
    id: "yara",
    name: "YARA",
    category: "malware",
    categoryLabel: "Malware Pattern Matching",
    license: "BSD-3-Clause",
    website: "https://virustotal.github.io/yara/",
    summary: "The pattern matching swiss-knife for malware researchers and threat hunters. Allows creation of textual, hexadecimal, and regular-expression signatures to classify malicious artifacts and process memory.",
    detectionRole: "Scans disk files, running process address spaces, email attachments, and CI/CD binaries for specific compile flags, obfuscated strings, embedded PE signatures, and wiper commands.",
    defenseRole: "Blocks malicious file drops at the mail gateway, prevents unapproved executable staging on endpoints, and powers automated quarantine hooks in enterprise EDR agents.",
    ruleFormat: "YARA Signature (.yar)",
    sampleRule: `rule Malicious_Wiper_Commands : Critical {
    meta:
        description = "Detects wiper commands destroying VSS backups and recovery bcd"
        author = "SOC Threat Engineering"
        reference = "MITRE T1490"
    strings:
        $vss1 = "vssadmin.exe delete shadows /all /quiet" ascii wide nocase
        $vss2 = "wmic shadowcopy delete" ascii wide nocase
        $bcd1 = "bcdedit.exe /set {default} recoveryenabled no" ascii wide nocase
    condition:
        2 of ($vss1, $vss2, $bcd1)
}`,
    linkedAttacks: [
      { num: 8, id: "rootkit", name: "Rootkit" },
      { num: 10, id: "keylogger", name: "Keylogger" },
      { num: 37, id: "keylogger-attack", name: "Keylogger Attack" },
      { num: 71, id: "linux-rootkit", name: "Linux Kernel Rootkit" },
      { num: 76, id: "macos-malware", name: "macOS Malware Attack" },
      { num: 108, id: "data-destruction", name: "Data Destruction & Wipers" }
    ]
  },
  {
    id: "volatility",
    name: "Volatility 3",
    category: "malware",
    categoryLabel: "Memory Forensics Framework",
    license: "GPLv2",
    website: "https://www.volatilityfoundation.org",
    summary: "The world's standard memory forensics framework for incident response and volatile RAM analysis across Windows, Linux, and macOS memory captures.",
    detectionRole: "Extracts injected shellcode, reveals hidden/unlinked processes (DKOM), audits kernel hook tables (SSDT), uncovers dumped LSASS passwords, and identifies active rootkit drivers.",
    defenseRole: "Provides ground-truth forensic evidence during high-severity incident triage to confirm active memory-only malware, validate complete containment, and extract IOCs for enterprise blocking.",
    ruleFormat: "Volatility 3 CLI Command",
    sampleRule: `# Extract Injected DLLs and Process Hollowing Artifacts
python3 vol.py -f memory.raw windows.malfind
python3 vol.py -f memory.raw windows.lsadump`,
    linkedAttacks: [
      { num: 6, id: "buffer-overflow", name: "Buffer Overflow" },
      { num: 8, id: "rootkit", name: "Rootkit" },
      { num: 68, id: "pass-the-hash", name: "Pass-the-Hash" },
      { num: 77, id: "macos-injection", name: "macOS Code Injection" },
      { num: 80, id: "spec-buffer-overflow", name: "Specialized Buffer Overflow" },
      { num: 83, id: "format-string", name: "Format String Attack" }
    ]
  },
  {
    id: "clamav",
    name: "ClamAV",
    category: "malware",
    categoryLabel: "Antivirus Engine",
    license: "GPLv2",
    website: "https://www.clamav.net",
    summary: "Open-source antivirus engine designed for scanning file systems, email server gateways, and web application file upload directories for trojans, viruses, and malicious attachments.",
    detectionRole: "Scans files against a database of millions of known virus hashes, unpacks compressed multi-format archives (zip, tar, rar, docx, pdf), and performs heuristic bytecode inspection.",
    defenseRole: "Automatically discards or quarantines infected multipart form uploads before they are persisted to S3 or internal storage arrays, preventing weaponized payload staging.",
    ruleFormat: "ClamAV Config Directive",
    sampleRule: `# /etc/clamav/clamd.conf: Automatic File Upload Quarantine
ScanMail yes
ScanArchive yes
AlertEncrypted yes
OnAccessExcludePath /proc
OnAccessIncludePath /var/www/uploads
OnAccessAction quarantine`,
    linkedAttacks: [
      { num: 10, id: "keylogger", name: "Keylogger" },
      { num: 76, id: "macos-malware", name: "macOS Malware Attack" },
      { num: 88, id: "security-misconfiguration", name: "Security Misconfiguration" },
      { num: 108, id: "data-destruction", name: "Data Destruction" }
    ]
  },

  // =========================================================================
  // 6. CLOUD, CONTAINER & SUPPLY CHAIN SECURITY
  // =========================================================================
  {
    id: "trivy",
    name: "Trivy",
    category: "cloud",
    categoryLabel: "Container & Vulnerability Scanner",
    license: "Apache 2.0",
    website: "https://trivy.dev",
    summary: "Comprehensive open-source security scanner by Aqua Security. Scans container images, file systems, Git repositories, virtual machine disks, and Kubernetes clusters for known vulnerabilities.",
    detectionRole: "Detects OS package CVEs, language-specific dependency flaws (npm, PyPI, Maven, Go), exposed API secrets, and misconfigured infrastructure-as-code files.",
    defenseRole: "Blocks vulnerable image deployment in CI/CD pipelines (exits with non-zero status code on CRITICAL CVEs) and enforces admission controller rejection in live Kubernetes clusters.",
    ruleFormat: "Trivy CI/CD Pipeline Command",
    sampleRule: `# Scan container image and block build on Critical CVEs
trivy image --severity CRITICAL,HIGH --exit-code 1 myapp:production`,
    linkedAttacks: [
      { num: 66, id: "missing-patch", name: "Missing Patch Exploitation" },
      { num: 88, id: "security-misconfiguration", name: "Security Misconfiguration" },
      { num: 89, id: "vulnerable-components", name: "Vulnerable & Outdated Components" },
      { num: 106, id: "s3-exposure", name: "S3 Bucket Exposure" }
    ]
  },
  {
    id: "checkov",
    name: "Checkov",
    category: "cloud",
    categoryLabel: "Infrastructure as Code (IaC) Scanner",
    license: "Apache 2.0",
    website: "https://www.checkov.io",
    summary: "Static code analysis tool for Infrastructure as Code (IaC). Evaluates Terraform, CloudFormation, Kubernetes, Helm, and ARM templates against hundreds of enterprise cloud security benchmarks.",
    detectionRole: "Identifies publicly accessible S3 buckets, unencrypted EBS storage volumes, open security groups (0.0.0.0/0), overly permissive IAM wildcard policies, and missing IMDSv2 enforcement.",
    defenseRole: "Halts CI/CD deployment pipelines before misconfigured infrastructure is provisioned to cloud environments, enforcing compliance with CIS, HIPAA, and SOC 2 standards.",
    ruleFormat: "Checkov Policy (Python / YAML)",
    sampleRule: `# Enforce S3 Bucket Encryption & Block Public Access
checkov -d ./terraform --check CKV_AWS_18,CKV_AWS_19,CKV_AWS_21`,
    linkedAttacks: [
      { num: 14, id: "ssrf", name: "Server-Side Request Forgery" },
      { num: 84, id: "broken-access-control", name: "Broken Access Control" },
      { num: 88, id: "security-misconfiguration", name: "Security Misconfiguration" },
      { num: 106, id: "s3-exposure", name: "S3 Bucket Public Exposure" },
      { num: 107, id: "snapshot-exfil", name: "Storage Snapshot Exfiltration" },
      { num: 109, id: "insecure-backup-storage", name: "Insecure Backup Storage" }
    ]
  },
  {
    id: "gitleaks",
    name: "Gitleaks",
    category: "cloud",
    categoryLabel: "Secret Scanner & Code Gate",
    license: "MIT",
    website: "https://github.com/gitleaks/gitleaks",
    summary: "Lightweight, ultra-fast SAST tool for detecting hardcoded secrets, API keys, private certificates, and authentication tokens in Git repositories and commit histories.",
    detectionRole: "Uses regex patterns and Shannon entropy scoring to flag leaked AWS credentials, SSH private keys, GitHub tokens, database passwords, and JWT signing secrets.",
    defenseRole: "Acts as a pre-commit git hook and CI pull request gate, actively rejecting commits that contain plaintext credentials before they enter source control.",
    ruleFormat: "Gitleaks Rule Configuration (.toml)",
    sampleRule: `[rules]
description = "Hardcoded AWS Access Key"
regex = '''(?i)(aws_access_key_id|aws_secret_access_key)['"\\s]*[:=]['"\\s]*([A-Z0-9]{20})'''
tags = ["key", "AWS", "secret"]`,
    linkedAttacks: [
      { num: 14, id: "ssrf", name: "Server-Side Request Forgery" },
      { num: 85, id: "cryptographic-failures", name: "Cryptographic Failures" },
      { num: 93, id: "ssrf-attack", name: "OWASP SSRF" },
      { num: 101, id: "blind-sql-injection", name: "Blind SQL Injection" },
      { num: 106, id: "s3-exposure", name: "S3 Bucket Exposure" }
    ]
  },

  // =========================================================================
  // 7. IDENTITY, SECRETS & AUTHENTICATION DEFENSE
  // =========================================================================
  {
    id: "keycloak",
    name: "Keycloak / Authelia",
    category: "identity",
    categoryLabel: "Identity Provider & MFA (IAM)",
    license: "Apache 2.0",
    website: "https://www.keycloak.org",
    summary: "Open-source Identity and Access Management (IAM) server. Provides single sign-on (SSO), user federation, OAuth 2.0 / OpenID Connect, and phishing-resistant multi-factor authentication (MFA).",
    detectionRole: "Logs authentication events, tracks failed login streaks, identifies abnormal session geographic shifts, and detects brute-force credential stuffing attempts.",
    defenseRole: "Enforces hardware FIDO2 WebAuthn / Passkeys (rendering credential stuffing useless), triggers adaptive step-up authentication, and enables instant global session invalidation.",
    ruleFormat: "Keycloak Brute-Force Policy",
    sampleRule: `# Keycloak Realm Brute Force Protection Policy
realm.setQuickLoginCheckMilliSeconds(1000);
realm.setMaxFailureWaitSeconds(900);
realm.setMinimumQuickLoginWaitSeconds(60);
realm.setFailureFactor(5);`,
    linkedAttacks: [
      { num: 31, id: "brute-force", name: "Brute-Force Attack" },
      { num: 33, id: "credential-stuffing", name: "Credential Stuffing" },
      { num: 34, id: "password-spraying", name: "Password Spraying" },
      { num: 84, id: "broken-access-control", name: "Broken Access Control" },
      { num: 90, id: "auth-failures", name: "Identification & Authentication Failures" }
    ]
  },
  {
    id: "openbao",
    name: "OpenBao (Vault Community)",
    category: "identity",
    categoryLabel: "Secrets Management & Encryption",
    license: "MPL 2.0 (Linux Foundation)",
    website: "https://openbao.org",
    summary: "Community-driven open-source software under the Linux Foundation managing secrets, certificates, and transit encryption. Provides dynamic ephemeral database credentials and centralized cryptographic key storage.",
    detectionRole: "Audits every cryptographic operation and secret readout. Generates tamper-evident access logs and alerts on unauthorized secret lookup bursts.",
    defenseRole: "Replaces static hardcoded credentials with just-in-time ephemeral tokens that expire after minutes; rotates database passwords automatically, preventing lateral privilege abuse.",
    ruleFormat: "OpenBao Dynamic Secret Policy",
    sampleRule: `# OpenBao / Vault ACL Policy: Ephemeral Database Role
path "database/creds/readonly-app" {
  capabilities = ["read"]
}`,
    linkedAttacks: [
      { num: 35, id: "offline-cracking", name: "Offline Password Cracking" },
      { num: 85, id: "cryptographic-failures", name: "Cryptographic Failures" },
      { num: 106, id: "s3-exposure", name: "S3 Bucket Exposure" },
      { num: 109, id: "insecure-backup-storage", name: "Insecure Backup Storage" },
      { num: 110, id: "unencrypted-storage", name: "Unencrypted Storage Access" }
    ]
  },

  // =========================================================================
  // 8. WIRELESS & LAYER 2 DEFENSE
  // =========================================================================
  {
    id: "kismet",
    name: "Kismet",
    category: "wireless",
    categoryLabel: "Wireless WIDS & Packet Sniffer",
    license: "GPLv2",
    website: "https://www.kismetwireless.net",
    summary: "Wireless network detector, sniffer, and intrusion detection system (WIDS) for Wi-Fi (802.11), Bluetooth, Zigbee, and software-defined radio (SDR) interfaces.",
    detectionRole: "Passively captures wireless packets, detects rogue access points, identifies unencrypted enterprise traffic, spots BSSID spoofing, and detects deauthentication denial-of-service frame storms.",
    defenseRole: "Alerts SOC teams to unauthorized rogue hotspots and Evil Twin access points on campus premises, outputting GPS mapping for physical sweeps.",
    ruleFormat: "Kismet Alert Config",
    sampleRule: `# Alert on 802.11 Deauthentication Frame Bursts
alert=DEAUTH_FLOOD,10,2/sec,"Possible Deauth DoS attack or WPA handshake capture attempt"`,
    linkedAttacks: [
      { num: 40, id: "evil-twin", name: "Evil Twin Attack" },
      { num: 42, id: "deauth-attack", name: "Deauthentication Attack" },
      { num: 45, id: "rogue-ap", name: "Rogue AP Attack" },
      { num: 46, id: "unauthorized-hotspots", name: "Unauthorized Hotspots" },
      { num: 47, id: "honeypot-ap", name: "Honeypot AP" }
    ]
  },

  // =========================================================================
  // 9. NETWORK SCANNING & RECONNAISSANCE
  // =========================================================================
  {
    id: "nmap",
    name: "Nmap",
    category: "scanning",
    categoryLabel: "Network & DB Scanning",
    license: "Nmap Public Source License / GPLv2",
    website: "https://nmap.org",
    summary: "The industry-standard open-source network scanner and service discovery tool. Discovers hosts, open TCP/UDP ports, running service versions, and OS fingerprints. In database testing, Nmap's Scripting Engine (NSE) audits MySQL, MSSQL, Oracle, and PostgreSQL configurations, finding blank passwords, unpatched database services, and cleartext database listeners.",
    detectionRole: "In defensive operations, defenders run Nmap for continuous attack surface management and database listener discovery. Detected on networks via Suricata/Snort SYN scan signatures, high rates of TCP RST packets in Zeek conn.log, and DB audit logs recording anomalous enumeration queries.",
    defenseRole: "Proactively audits perimeter firewalls, identifies shadow IT and rogue database listeners, verifies that databases are restricted to localhost or isolated private subnets, and tests for default blank administrator credentials.",
    ruleFormat: "Nmap DB Audit Command & Snort 3 Detection Rule",
    sampleRule: `# 1. Database Security Testing with Nmap NSE Scripts:
nmap -p 3306,1433,1521,5432 --script "mysql-info,mysql-empty-password,ms-sql-info,pgsql-databases" -sV 192.168.1.0/24

# 2. Snort 3 Rule to detect Nmap SYN Stealth Port Scan:
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-FOSS-NMAP High-Rate TCP Port Scanning Detected";
    flags:S;
    threshold: type both, track by_src, count 30, seconds 5;
    classtype:attempted-recon;
    sid:2026201;
    rev:1;
)`,
    linkedAttacks: [
      { num: 1, id: "dos", name: "Denial-of-Service" },
      { num: 5, id: "port-scanning", name: "Port Scanning" },
      { num: 65, id: "null-session", name: "Null Session Attack" },
      { num: 66, id: "missing-patch", name: "Missing Patch Exploitation" },
      { num: 73, id: "ssh-bruteforce", name: "SSH Brute-Force" },
      { num: 88, id: "security-misconfiguration", name: "Security Misconfiguration" },
      { num: 107, id: "unencrypted-database-traffic", name: "Unencrypted Database Storage & Traffic" },
      { num: 110, id: "default-credentials", name: "Default & Hardcoded Credentials" }
    ]
  },
  {
    id: "netdiscover",
    name: "Netdiscover",
    category: "scanning",
    categoryLabel: "Network Scanning",
    license: "GPLv3",
    website: "https://github.com/netdiscover-scanner/netdiscover",
    summary: "Active and passive ARP reconnaissance tool designed for wireless and switched Ethernet networks. Identifies active live hosts on local subnets even when ICMP ping is blocked.",
    detectionRole: "Discovers active hosts by sending sequential ARP 'who-has' requests or passively sniffing ARP broadcasts. Detected on switches and IDS via high-frequency ARP broadcast floods originating from a single MAC address.",
    defenseRole: "Enables security administrators to audit subnets for rogue static IPs and unmanaged devices; defended on switches via Dynamic ARP Inspection (DAI) and Arpwatch.",
    ruleFormat: "Netdiscover Command & Arpwatch Detection",
    sampleRule: `# 1. Netdiscover active scanning on subnet:
netdiscover -r 192.168.1.0/24 -i eth0

# 2. Arpwatch alert for suspicious host discovery sweep:
arpwatch: new station 192.168.1.185 00:0c:29:ff:ee:dd eth0`,
    linkedAttacks: [
      { num: 3, id: "mitm", name: "Man-in-the-Middle" },
      { num: 5, id: "port-scanning", name: "Port Scanning" },
      { num: 50, id: "arp-spoofing", name: "ARP Spoofing" },
      { num: 51, id: "mac-flooding", name: "MAC Flooding" }
    ]
  },

  // =========================================================================
  // 10. PASSWORD CRACKING & RECOVERY AUDITING
  // =========================================================================
  {
    id: "john",
    name: "John the Ripper",
    category: "password",
    categoryLabel: "Password Cracking",
    license: "GPLv2",
    website: "https://www.openwall.com/john/",
    summary: "High-speed open-source password security auditing and hash-cracking tool. Tests password strength across hundreds of hash and cipher types including Unix crypt, Windows NTLM, Kerberos, and macOS hashes.",
    detectionRole: "Used defensively by enterprise directory administrators to crack exported Active Directory NTDS.dit or Linux /etc/shadow hashes in an isolated environment, proactively identifying weak and compromised user credentials.",
    defenseRole: "Proactive password strength enforcement; informs policy to migrate password storage to memory-hard Argon2id or bcrypt, and mandates hardware FIDO2 passkeys.",
    ruleFormat: "John the Ripper Execution & Sigma Audit Rule",
    sampleRule: `# 1. Audit enterprise password hashes against dictionary with rules:
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes.txt

# 2. Sigma Rule: Detect Extraction of NTDS.dit (Prerequisite for offline cracking):
title: Active Directory Database Extraction (ntdsutil)
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\ntdsutil.exe'
        CommandLine|contains: 'ac i ntds'
    condition: selection
level: critical`,
    linkedAttacks: [
      { num: 31, id: "brute-force", name: "Brute-Force Attack" },
      { num: 32, id: "dictionary-attack", name: "Dictionary Attack" },
      { num: 35, id: "offline-cracking", name: "Offline Password Cracking" },
      { num: 36, id: "rainbow-table", name: "Rainbow Table Attack" },
      { num: 38, id: "hybrid-attack", name: "Hybrid Attack" },
      { num: 68, id: "pass-the-hash", name: "Pass-the-Hash" },
      { num: 69, id: "kerberoasting", name: "Kerberoasting" }
    ]
  },
  {
    id: "hashcat",
    name: "Hashcat",
    category: "password",
    categoryLabel: "Password Cracking",
    license: "MIT",
    website: "https://hashcat.net/hashcat/",
    summary: "The world's fastest GPU-accelerated password recovery and hash-cracking utility. Supports multi-GPU parallel processing across over 350 cryptographic hashing algorithms (NTLM, Kerberos 5 TGS, WPA2/WPA3 PBKDF2, SHA-512 crypt).",
    detectionRole: "Employed by defensive teams to audit Active Directory Kerberos TGS-REP service ticket hashes (Kerberoasting) and WPA handshakes to verify that service account passwords meet complexity thresholds.",
    defenseRole: "Validates password entropy against dictionary, combinator, and mask attacks; drives migration to 25+ character service account passphrases and Group Managed Service Accounts (gMSA).",
    ruleFormat: "Hashcat Command & Telemetry Detection",
    sampleRule: `# 1. Audit Kerberoast TGS-REP ticket hash using GPU (Mode 13100):
hashcat -m 13100 -a 0 kerberos_tgs.hash passwords.txt -r rules/best64.rule

# 2. Sysmon / Event ID 4769 RC4 TGS Request Anomaly Query:
index=wineventlog EventCode=4769 TicketEncryptionType=0x17
| stats count by Service_Name, Client_Address
| where count > 10`,
    linkedAttacks: [
      { num: 35, id: "offline-cracking", name: "Offline Password Cracking" },
      { num: 36, id: "rainbow-table", name: "Rainbow Table Attack" },
      { num: 38, id: "hybrid-attack", name: "Hybrid Attack" },
      { num: 39, id: "mask-attack", name: "Mask Attack" },
      { num: 69, id: "kerberoasting", name: "Kerberoasting" }
    ]
  },

  // =========================================================================
  // 11. SOCIAL ENGINEERING & PHISHING SIMULATION
  // =========================================================================
  {
    id: "setoolkit",
    name: "SET (Social-Engineer Toolkit)",
    category: "social",
    categoryLabel: "Social Engineering",
    license: "BSD-3-Clause",
    website: "https://github.com/trustedsec/social-engineer-toolkit",
    summary: "Open-source penetration testing framework created by TrustedSec specifically focused on social-engineering attack vectors. Supports authorized simulations including credential harvesting and Spear-Phishing campaigns.",
    detectionRole: "Generates cloned login portals and payload vectors to test SOC detection capabilities. Detected via email gateway URL rewrites, newly registered domain (NRD) alerts, and SIEM monitoring for anomalous web session logins.",
    defenseRole: "Validates employee susceptibility in controlled environments; proves necessity of FIDO2 WebAuthn / Passkeys (which are impervious to credential harvesting portals) and automated DMARC/SPF enforcement.",
    ruleFormat: "Suricata / Zeek Phishing Portal Detection",
    sampleRule: `# Suricata: Detect Inbound Traffic to Cloned Phishing Form
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-FOSS-SET Suspicious POST to Cloned Web Login Form";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"username="; http_client_body;
    content:"password="; http_client_body;
    threshold: type limit, track by_src, count 1, seconds 60;
    classtype:bad-unknown;
    sid:2026202;
    rev:1;
)`,
    linkedAttacks: [
      { num: 2, id: "aitm-mfa-bypass", name: "Phishing & AiTM MFA Bypass" },
      { num: 10, id: "keylogger", name: "Keylogger" },
      { num: 33, id: "credential-stuffing", name: "Credential Stuffing" },
      { num: 37, id: "keylogger-attack", name: "Keylogger Attack" },
      { num: 90, id: "auth-failures", name: "Authentication Failures" }
    ]
  },
  {
    id: "king-phisher",
    name: "King Phisher",
    category: "social",
    categoryLabel: "Social Engineering",
    license: "BSD-3-Clause",
    website: "https://github.com/rsmthreat/king-phisher",
    summary: "Enterprise-grade phishing campaign toolkit designed to simulate realistic adversary phishing attacks and manage security awareness training programs across corporate personnel.",
    detectionRole: "Tracks email open telemetry, credential harvesting hits, two-factor token submissions, and user reporting rates. Integrates with enterprise SMTP servers to evaluate email gateway filtering rules.",
    defenseRole: "Identifies high-risk departments requiring targeted security training; validates secure email gateway (SEG) filtering efficacy, DNS Blacklist (DNSBL) speed, and browser safe-browsing protections.",
    ruleFormat: "Mail Gateway & SPF/DMARC Defense Policy",
    sampleRule: `# 1. Enforce Strict DMARC Policy in DNS to block unauthorized email spoofing:
_dmarc.company.com. IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@company.com"

# 2. Exim / Postfix Header Filter for Fake Login Notifications:
warn message = X-Phish-Warning: External sender claiming internal domain
     condition = \${if match{\$h_from:}{company\\\\.com}{yes}{no}}`,
    linkedAttacks: [
      { num: 2, id: "aitm-mfa-bypass", name: "Phishing & AiTM MFA Bypass" },
      { num: 31, id: "brute-force", name: "Brute-Force Attack" },
      { num: 90, id: "auth-failures", name: "Authentication Failures" }
    ]
  },
  {
    id: "gophish",
    name: "Gophish",
    category: "social",
    categoryLabel: "Social Engineering",
    license: "MIT",
    website: "https://getgophish.com",
    summary: "Powerful, open-source phishing simulation framework. Built in Go, it allows security teams and system administrators to easily create and track realistic user awareness campaigns in minutes.",
    detectionRole: "Tracks real-time user interaction: Email Sent, Email Opened, Link Clicked, Credentials Submitted, and Email Reported. Feeds SOC metrics on enterprise resilience to spear-phishing.",
    defenseRole: "Trains employees to recognize adversary social engineering tactics, builds muscle memory for reporting phishing emails via Outlook/Gmail add-ins, and demonstrates the necessity of phishing-resistant Passkeys.",
    ruleFormat: "Gophish Webhook Handler & Email Reporting Rule",
    sampleRule: `# Python Webhook Handler for Gophish Simulation Telemetry:
import hmac, hashlib
def verify_gophish_event(payload, signature, secret):
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)

# Logs user 'Clicked Link' or 'Submitted Data' events directly to SIEM`,
    linkedAttacks: [
      { num: 2, id: "aitm-mfa-bypass", name: "Phishing & AiTM MFA Bypass" },
      { num: 90, id: "auth-failures", name: "Authentication Failures" },
      { num: 91, id: "integrity-failures", name: "Software & Data Integrity Failures" }
    ]
  },

  // =========================================================================
  // 12. WEB APPLICATION SECURITY TESTING (OWASP / DAST / FUZZING)
  // =========================================================================
  {
    id: "burp-suite",
    name: "Burp Suite (Community / Open Testing)",
    category: "webapp-test",
    categoryLabel: "Web App Testing",
    license: "PortSwigger Community / Open Extensibility API",
    website: "https://portswigger.net/burp/communitydownload",
    summary: "The industry-standard interactive web application security testing workbench. Features an intercepting HTTP proxy, repeater, intruder, and extensibility engine used by security professionals to uncover OWASP Top 10 vulnerabilities, broken access controls, and authentication flaws.",
    detectionRole: "Identifies automated scanning signatures, repetitive parameter tampering patterns, intruder payload markers, and atypical HTTP header ordering in web server access logs and WAF telemetry.",
    defenseRole: "Validates enterprise WAF rule strictness (ModSecurity CRS), CSRF token enforcement, secure cookie flags (SameSite=Strict, Secure, HttpOnly), and strict schema parameter validation on public APIs.",
    ruleFormat: "ModSecurity / WAF Rule for Intercept & Scanner Payloads",
    sampleRule: `# ModSecurity Rule: Block Burp Suite Automated Scanner & Repeater Probing
SecRule REQUEST_HEADERS:User-Agent "@contains burp" \\
    "id:2026301,phase:1,deny,status:403,log,msg:'SEC-WAF: Burp Suite Automated Scanner User-Agent Detected'"

SecRule ARGS "@rx (?i)(?:union\\s+all\\s+select|<script[^>]*>|(?:\\.\\./){3,})" \\
    "id:2026302,phase:2,deny,status:400,log,msg:'SEC-WAF: Core Web Exploit Payload Intercepted from Dynamic Test Engine'"`,
    linkedAttacks: [
      { num: 11, id: "sql-injection", name: "SQL Injection (SQLi)" },
      { num: 12, id: "xss", name: "Cross-Site Scripting (XSS)" },
      { num: 13, id: "csrf", name: "Cross-Site Request Forgery (CSRF)" },
      { num: 14, id: "ssrf", name: "Server-Side Request Forgery (SSRF)" },
      { num: 84, id: "broken-access-control", name: "Broken Access Control" },
      { num: 88, id: "security-misconfiguration", name: "Security Misconfiguration" },
      { num: 94, id: "http-request-smuggling", name: "HTTP Request Smuggling" }
    ]
  },
  {
    id: "owasp-zap",
    name: "OWASP ZAP (Zed Attack Proxy)",
    category: "webapp-test",
    categoryLabel: "Web App Testing",
    license: "Apache-2.0",
    website: "https://www.zaproxy.org",
    summary: "World's most widely used 100% open-source dynamic application security testing (DAST) tool. Maintained by the OWASP foundation and Linux Foundation, ZAP provides automated spidering, active/passive vulnerability scanning, and seamless CI/CD pipeline integration.",
    detectionRole: "Monitors for ZAP active scan signatures, spider crawling rates, and high-frequency parameter fuzzing requests against web applications. Correlated through WAF and access log analytics.",
    defenseRole: "Continuously asserts defensive posture in DevSecOps pipelines; fails builds if missing Security Headers (HSTS, CSP, X-Frame-Options), detects exposed administrative endpoints, and verifies session management.",
    ruleFormat: "OWASP ZAP DevSecOps CI Automation & ModSecurity Rule",
    sampleRule: `# 1. OWASP ZAP Automation Framework (zap.yaml) for CI/CD Pipeline Scanning:
env:
  contexts:
    - name: "Production-Staging"
      urls: ["https://staging.internal.corp"]
      includePaths: ["https://staging.internal.corp/.*"]
jobs:
  - type: passiveScan-config
    parameters:
      maxAlertsPerRule: 10
  - type: spider
    parameters:
      maxDuration: 15
  - type: activeScan
    parameters:
      policy: "High-Confidence-Web-Attacks"

# 2. ModSecurity: Detect ZAP Scanner Default Header
# SecRule REQUEST_HEADERS:User-Agent "@contains OWASP ZAP" "id:2026303,phase:1,deny,status:403,msg:'ZAP Scan Detected'"`,
    linkedAttacks: [
      { num: 12, id: "xss", name: "Cross-Site Scripting (XSS)" },
      { num: 14, id: "ssrf", name: "Server-Side Request Forgery (SSRF)" },
      { num: 86, id: "injection", name: "OWASP Injection Flaws" },
      { num: 88, id: "security-misconfiguration", name: "Security Misconfiguration" },
      { num: 89, id: "vuln-outdated-components", name: "Vulnerable Components" }
    ]
  },
  {
    id: "nikto",
    name: "Nikto Web Server Scanner",
    category: "webapp-test",
    categoryLabel: "Web App Testing",
    license: "GPL-2.0",
    website: "https://github.com/sullo/nikto",
    summary: "Classic open-source web server scanner that tests for over 6,700 potentially dangerous files and programs, outdated server components, configuration errors (such as enabled HTTP TRACE/DEBUG methods), and default server installations.",
    detectionRole: "Generates distinct, high-frequency 404 Not Found error spikes and attempts to retrieve known backup files (.git, .env, .bak, /admin/, /manager/html). Readily detected via SIEM rate analysis and Fail2ban filters.",
    defenseRole: "Audits web server configurations (Apache, Nginx, IIS) to ensure dangerous HTTP methods are disabled, default admin consoles are removed, and server identification banners are masked.",
    ruleFormat: "Fail2ban Filter & Nginx Hardening Configuration",
    sampleRule: `# 1. Fail2ban Filter for Nikto Rapid 404 Probing (/etc/fail2ban/filter.d/nikto-scanner.conf):
[Definition]
failregex = ^<HOST> - .* "(GET|POST|HEAD) /.*" (404|403) .* "Nikto.*"
            ^<HOST> - .* "(GET|POST|HEAD) /.*(\\.git|\\.env|\\.bak|test\\.php).*" (404|403)
ignoreregex =

# 2. Nginx Defense: Disable Dangerous HTTP Methods & Hide Version Banners:
# server_tokens off;
# if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE)$) { return 405; }`,
    linkedAttacks: [
      { num: 66, id: "missing-patch", name: "Missing Patch / Known Vulnerability" },
      { num: 88, id: "security-misconfiguration", name: "Security Misconfiguration" },
      { num: 89, id: "vuln-outdated-components", name: "Vulnerable Components" },
      { num: 98, id: "directory-traversal", name: "Directory Traversal" },
      { num: 110, id: "default-credentials", name: "Default & Hardcoded Credentials" }
    ]
  },
  {
    id: "sqlmap",
    name: "SQLmap (SQL Injection & DB Takeover)",
    category: "webapp-test",
    categoryLabel: "Web & DB Testing",
    license: "GPL-2.0",
    website: "https://sqlmap.org",
    summary: "The premier open-source penetration testing tool that automates the detection and exploitation of SQL injection vulnerabilities and the takeover of database servers across MySQL, Oracle, PostgreSQL, Microsoft SQL Server, SQLite, and more.",
    detectionRole: "Generates distinctive diagnostic payloads: time-based blind sleep injections (SLEEP, WAITFOR DELAY), stacked queries, Boolean error probes, and UNION SELECT enumerations visible in database slow query logs and WAF telemetry.",
    defenseRole: "Validates absolute elimination of dynamic SQL concatenation in codebases; enforces 100% parameterized prepared statements (PDO, PreparedStatement), least-privilege DB users, and WAF SQLi virtual patching.",
    ruleFormat: "ModSecurity CRS & PostgreSQL Query Audit Configuration",
    sampleRule: `# ModSecurity OWASP Core Rule Set: Block SQLmap Automated SQL Injection
SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \\
    "id:2026304,phase:1,deny,status:403,log,msg:'SEC-WAF: SQLmap Automated Scanner Detected'"

SecRule ARGS "@rx (?i)(?:waitfor\\s+delay\\s+'[0-9:]+'|pg_sleep\\([0-9]+\\)|sleep\\([0-9]+\\)|benchmark\\([0-9]+,)" \\
    "id:2026305,phase:2,deny,status:400,log,msg:'SEC-WAF: Time-Based Blind SQL Injection Payload Detected'"`,
    linkedAttacks: [
      { num: 11, id: "sql-injection", name: "SQL Injection (SQLi)" },
      { num: 86, id: "injection", name: "OWASP Injection Flaws" },
      { num: 101, id: "blind-sql-injection", name: "Blind SQL Injection" },
      { num: 102, id: "second-order-sql-injection", name: "Second-Order SQL Injection" },
      { num: 103, id: "xp-cmdshell", name: "xp_cmdshell Remote Execution" },
      { num: 104, id: "db-priv-esc", name: "Database Privilege Escalation" }
    ]
  },

  // =========================================================================
  // 13. DATABASE SECURITY TESTING & POST-EXPLOITATION
  // =========================================================================
  {
    id: "metasploit",
    name: "Metasploit Framework (Exploitation & DB Auditing)",
    category: "db-test",
    categoryLabel: "Database Security Testing",
    license: "BSD-3-Clause",
    website: "https://www.metasploit.com",
    summary: "The world's most widely used open-source penetration testing framework. Provides modular payloads, auxiliary database scanners (MSSQL, MySQL, Postgres, Oracle), and post-exploitation modules to verify database vulnerabilities and lateral movement paths.",
    detectionRole: "Detected via endpoint EDR monitoring for unauthorized process spawning under database service accounts (sqlservr.exe spawning cmd.exe or powershell.exe), network IDS signatures on DB ports, and meterpreter shellcode in memory.",
    defenseRole: "Proves necessity of disabling dangerous stored procedures (sp_dropextendedproc 'xp_cmdshell'), restricting database service account privileges, isolating DB instances on dedicated VLANs, and applying zero-trust network policies.",
    ruleFormat: "Sigma Rule: Detect Database Service Spawning Command Shell",
    sampleRule: `# Sigma Rule: Detect MSSQL / MySQL Spawning Shell or LOLBAS (Metasploit xp_cmdshell)
title: Database Engine Spawning Child Command Shell
id: e8a9b2c1-3d4f-4e5a-9b1c-7f8a9e0d1c2b
status: production
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\sqlservr.exe'
            - '\\mysqld.exe'
            - '\\postgres.exe'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059.001`,
    linkedAttacks: [
      { num: 6, id: "buffer-overflow", name: "Buffer Overflow" },
      { num: 15, id: "rce", name: "Remote Code Execution (RCE)" },
      { num: 65, id: "null-session", name: "Null Session Attack" },
      { num: 66, id: "missing-patch", name: "Missing Patch / Vulnerability" },
      { num: 103, id: "xp-cmdshell", name: "xp_cmdshell Remote Execution" },
      { num: 104, id: "db-priv-esc", name: "Database Privilege Escalation" },
      { num: 108, id: "sql-server-link-abuse", name: "Linked Database Server Abuse" }
    ]
  },
  {
    id: "sqlite3",
    name: "SQLite3 (Database Inspection & Forensics)",
    category: "db-test",
    categoryLabel: "Database Security Testing",
    license: "Public Domain (Open-Source)",
    website: "https://www.sqlite.org",
    summary: "The ubiquitous self-contained SQL database engine CLI and security inspection utility. Utilized for analyzing local database configurations, inspecting mobile and browser SQLite databases for unencrypted credential leakage, performing integrity verifications, and auditing write-ahead logs (WAL).",
    detectionRole: "Audits file-level permissions on SQLite database files, verifies cryptographic pragma settings, detects malformed database headers, and monitors for suspicious direct reads of sensitive local storage files.",
    defenseRole: "Enforces database file encryption (SQLCipher / SQLite Encryption Extension), configures PRAGMA secure_delete=ON to prevent unallocated space data recovery, and conducts integrity verification checks in forensic response.",
    ruleFormat: "SQLite3 Security Hardening & Forensic Audit Script",
    sampleRule: `-- 1. SQLite3 Defensive Security Hardening Pragmas:
-- Securely overwrite deleted records to zero to prevent unallocated data recovery:
PRAGMA secure_delete = ON;

-- Verify database file integrity against corruption or unauthorized tampering:
PRAGMA integrity_check;

-- Restrict temporary storage to memory only (avoid writing temp data to unencrypted disk):
PRAGMA temp_store = MEMORY;

-- 2. Bash/Auditd: Detect unauthorized file access to SQLite credential databases:
# auditctl -w /var/lib/app/database.sqlite -p rwxa -k sqlite_access_audit`,
    linkedAttacks: [
      { num: 85, id: "cryptographic-failures", name: "Cryptographic Failures" },
      { num: 88, id: "security-misconfiguration", name: "Security Misconfiguration" },
      { num: 91, id: "integrity-failures", name: "Software & Data Integrity Failures" },
      { num: 107, id: "unencrypted-database-traffic", name: "Unencrypted Database Storage & Traffic" },
      { num: 109, id: "insecure-backup-storage", name: "Insecure Database Backup Storage" }
    ]
  }
];

// =============================================================================
// STATE MANAGEMENT & FILTERING
// =============================================================================

let currentToolsFilter = "all";
let currentToolsSearch = "";

/**
 * Renders the entire FOSS Tools Mode layout
 */
function renderToolsLayout() {
  const container = document.getElementById("tools-layout");
  if (!container) return;

  container.innerHTML = `
    <!-- Hero Banner -->
    <section class="tools-hero">
      <div class="tools-hero-left">
        <div class="tools-hero-badge">
          <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span>FOSS DEFENSE STACK · DETECTION & HARDENING</span>
        </div>
        <h2 class="tools-hero-title">Common FOSS Tools for Threat Detection & Defense</h2>
        <p class="tools-hero-subtitle">
          Auditable, open-source security toolchains, intrusion detection/prevention systems (IDS/IPS), host EDR,
          web application firewalls (WAF), and forensic frameworks cross-mapped to all 95 threat vectors in this application.
        </p>
      </div>

      <div class="tools-search-wrapper">
        <div class="search-box tools-search-box">
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <input type="text" id="tools-search-input" placeholder="Search tools (Suricata, Wazuh, Falco, YARA, SQLi)..." autocomplete="off" value="${escapeHtml(currentToolsSearch)}">
          <button id="tools-clear-search-btn" class="clear-btn" aria-label="Clear Tools Search" style="${currentToolsSearch ? 'display: block;' : 'display: none;'}">&times;</button>
        </div>
      </div>
    </section>

    <!-- Category Filter Bar -->
    <div class="tools-category-bar" id="tools-category-bar" role="toolbar" aria-label="Tools Category Filter">
      <!-- Filter pills rendered below -->
    </div>

    <!-- Quick Stats Bar -->
    <div class="tools-stats-bar">
      <div class="tools-stat-item">
        <span class="stat-num" id="tools-showing-count">${FOSS_TOOLS_DATA.length}</span>
        <span class="stat-label">Engines Displayed</span>
      </div>
      <div class="tools-stat-item">
        <span class="stat-num">100%</span>
        <span class="stat-label">Open-Source & Auditable</span>
      </div>
      <div class="tools-stat-item">
        <span class="stat-num">95 Vectors</span>
        <span class="stat-label">Threat Coverage</span>
      </div>
      <div class="tools-stat-item">
        <span class="stat-num">Active Drop</span>
        <span class="stat-label">Automated Defense</span>
      </div>
    </div>

    <!-- Tools Cards Grid -->
    <div class="tools-cards-grid" id="tools-cards-grid">
      <!-- Tool cards rendered below -->
    </div>
  `;

  const countBadge = document.getElementById("mode-tools-count");
  if (countBadge) countBadge.textContent = `${FOSS_TOOLS_DATA.length} Tools`;
  const countPill = document.getElementById("tools-count-pill");
  if (countPill) countPill.textContent = `${FOSS_TOOLS_DATA.length} Engines`;

  renderToolsCategoryPills();
  renderToolsGrid();
  bindToolsEvents();
}

/**
 * Renders the filter buttons for categories
 */
function renderToolsCategoryPills() {
  const container = document.getElementById("tools-category-bar");
  if (!container) return;

  const categories = [
    { id: "all", label: "All Tools", count: FOSS_TOOLS_DATA.length },
    { id: "scanning", label: "Network Scanning", count: FOSS_TOOLS_DATA.filter(t => t.category === "scanning").length },
    { id: "password", label: "Password Cracking", count: FOSS_TOOLS_DATA.filter(t => t.category === "password").length },
    { id: "social", label: "Social Engineering", count: FOSS_TOOLS_DATA.filter(t => t.category === "social").length },
    { id: "webapp-test", label: "Web App Testing", count: FOSS_TOOLS_DATA.filter(t => t.category === "webapp-test" || t.id === "sqlmap").length },
    { id: "db-test", label: "Database Testing", count: FOSS_TOOLS_DATA.filter(t => t.category === "db-test" || t.id === "nmap" || t.id === "sqlmap").length },
    { id: "network", label: "Network IDS / IPS", count: FOSS_TOOLS_DATA.filter(t => t.category === "network").length },
    { id: "host", label: "Host XDR & EDR", count: FOSS_TOOLS_DATA.filter(t => t.category === "host").length },
    { id: "web", label: "Web & WAF", count: FOSS_TOOLS_DATA.filter(t => t.category === "web").length },
    { id: "siem", label: "SIEM & Detection", count: FOSS_TOOLS_DATA.filter(t => t.category === "siem").length },
    { id: "malware", label: "Malware & Forensics", count: FOSS_TOOLS_DATA.filter(t => t.category === "malware").length },
    { id: "cloud", label: "Cloud & Containers", count: FOSS_TOOLS_DATA.filter(t => t.category === "cloud").length },
    { id: "identity", label: "Identity & Secrets", count: FOSS_TOOLS_DATA.filter(t => t.category === "identity").length },
    { id: "wireless", label: "Wireless & L2", count: FOSS_TOOLS_DATA.filter(t => t.category === "wireless").length }
  ];

  container.innerHTML = categories.map(cat => `
    <button class="filter-pill ${currentToolsFilter === cat.id ? 'active' : ''}" data-category="${cat.id}">
      <span>${cat.label}</span>
      <span class="pill-count">(${cat.count})</span>
    </button>
  `).join("");

  container.querySelectorAll(".filter-pill").forEach(btn => {
    btn.addEventListener("click", () => {
      currentToolsFilter = btn.getAttribute("data-category");
      renderToolsCategoryPills();
      renderToolsGrid();
    });
  });
}

/**
 * Filters and renders tool cards
 */
function renderToolsGrid() {
  const grid = document.getElementById("tools-cards-grid");
  const countEl = document.getElementById("tools-showing-count");
  if (!grid) return;

  const query = currentToolsSearch.toLowerCase().trim();

  const filtered = FOSS_TOOLS_DATA.filter(tool => {
    // Category match
    if (currentToolsFilter !== "all") {
      if (currentToolsFilter === "db-test") {
        if (tool.category !== "db-test" && tool.id !== "nmap" && tool.id !== "sqlmap") {
          return false;
        }
      } else if (currentToolsFilter === "webapp-test") {
        if (tool.category !== "webapp-test" && tool.id !== "sqlmap") {
          return false;
        }
      } else if (tool.category !== currentToolsFilter) {
        return false;
      }
    }
    // Search match
    if (!query) return true;

    const matchName = tool.name.toLowerCase().includes(query);
    const matchCategory = tool.categoryLabel.toLowerCase().includes(query);
    const matchSummary = tool.summary.toLowerCase().includes(query);
    const matchDetection = tool.detectionRole.toLowerCase().includes(query);
    const matchDefense = tool.defenseRole.toLowerCase().includes(query);
    const matchAttacks = tool.linkedAttacks.some(a => 
      a.name.toLowerCase().includes(query) || 
      a.id.toLowerCase().includes(query) || 
      `#${a.num}`.includes(query) || 
      `${a.num}` === query
    );

    return matchName || matchCategory || matchSummary || matchDetection || matchDefense || matchAttacks;
  });

  if (countEl) {
    countEl.textContent = filtered.length;
  }

  if (filtered.length === 0) {
    grid.innerHTML = `
      <div class="tools-empty-state">
        <svg viewBox="0 0 24 24" width="48" height="48" stroke="currentColor" fill="none" stroke-width="1.5">
          <circle cx="11" cy="11" r="8"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        </svg>
        <h3>No matching FOSS tools found</h3>
        <p>Try searching by tool name (e.g., 'Suricata', 'Wazuh', 'YARA') or threat vector (e.g., 'SQLi', 'Ransomware', 'SSRF').</p>
        <button class="filter-pill active" onclick="resetToolsFilters()">Reset Filters</button>
      </div>
    `;
    return;
  }

  grid.innerHTML = filtered.map(tool => {
    // Generate linked attack tags
    const attacksHtml = tool.linkedAttacks.map(att => {
      const numStr = att.num < 10 ? `0${att.num}` : `${att.num}`;
      return `
        <button class="tool-attack-badge" onclick="jumpToLearningAttack('${att.id}')" title="View Attack #${numStr} (${att.name}) in Learning Mode">
          <span class="attack-badge-num">#${numStr}</span>
          <span class="attack-badge-text">${att.name}</span>
          <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" fill="none" stroke-width="2">
            <path d="M5 12h14M12 5l7 7-7 7"/>
          </svg>
        </button>
      `;
    }).join("");

    return `
      <article class="tool-card" id="tool-${tool.id}">
        <div class="tool-card-header">
          <div class="tool-title-row">
            <div class="tool-icon-bubble">
              <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" fill="none" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <div>
              <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <h3 class="tool-name">${tool.name}</h3>
                <span class="tool-category-badge ${tool.category}">${tool.categoryLabel}</span>
                <span class="tool-license-badge">${tool.license}</span>
              </div>
              <a href="${tool.website}" target="_blank" rel="noopener noreferrer" class="tool-website-link" title="Open official website">
                <span>${tool.website.replace('https://', '')}</span>
                <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" fill="none" stroke-width="2">
                  <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                  <polyline points="15 3 21 3 21 9"></polyline>
                  <line x1="10" y1="14" x2="21" y2="3"></line>
                </svg>
              </a>
            </div>
          </div>
        </div>

        <p class="tool-summary">${tool.summary}</p>

        <!-- Detection & Defense 2-Col Grid -->
        <div class="tool-capabilities-grid">
          <div class="tool-cap-box detection">
            <div class="tool-cap-title">
              <svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" fill="none" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
              </svg>
              <span>DETECTION TELEMETRY</span>
            </div>
            <p class="tool-cap-text">${tool.detectionRole}</p>
          </div>

          <div class="tool-cap-box defense">
            <div class="tool-cap-title">
              <svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" fill="none" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>ACTIVE ENFORCEMENT & DEFENSE</span>
            </div>
            <p class="tool-cap-text">${tool.defenseRole}</p>
          </div>
        </div>

        <!-- Sample Detection Rule / Config Preview -->
        <div class="tool-code-preview-wrap">
          <div class="tool-code-header">
            <span class="tool-code-format">${tool.ruleFormat}</span>
            <button class="copy-tool-rule-btn" data-tool-id="${tool.id}" title="Copy configuration snippet to clipboard">
              <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
              <span>Copy Rule</span>
            </button>
          </div>
          <pre class="tool-code-pre"><code>${escapeHtml(tool.sampleRule)}</code></pre>
        </div>

        <!-- Linked Threat Vectors Section -->
        <div class="tool-linked-section">
          <div class="tool-linked-header">
            <span class="tool-linked-title">Linked Attacks Covered (${tool.linkedAttacks.length}):</span>
            <span class="tool-linked-hint">Click any badge to jump to attack dossier</span>
          </div>
          <div class="tool-linked-badges">
            ${attacksHtml}
          </div>
        </div>
      </article>
    `;
  }).join("");

  // Attach copy listeners
  grid.querySelectorAll(".copy-tool-rule-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const toolId = btn.getAttribute("data-tool-id");
      const tool = FOSS_TOOLS_DATA.find(t => t.id === toolId);
      if (tool && tool.sampleRule) {
        navigator.clipboard.writeText(tool.sampleRule).then(() => {
          if (typeof showToast === "function") {
            showToast(`${tool.name} detection rule copied to clipboard!`);
          }
        }).catch(err => console.error("Clipboard copy error:", err));
      }
    });
  });
}

/**
 * Binds search and clear button events
 */
function bindToolsEvents() {
  const searchInput = document.getElementById("tools-search-input");
  const clearBtn = document.getElementById("tools-clear-search-btn");

  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      currentToolsSearch = e.target.value;
      if (clearBtn) {
        clearBtn.style.display = currentToolsSearch ? "block" : "none";
      }
      renderToolsGrid();
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      currentToolsSearch = "";
      if (searchInput) searchInput.value = "";
      clearBtn.style.display = "none";
      renderToolsGrid();
    });
  }
}

function resetToolsFilters() {
  currentToolsFilter = "all";
  currentToolsSearch = "";
  renderToolsCategoryPills();
  const searchInput = document.getElementById("tools-search-input");
  if (searchInput) searchInput.value = "";
  const clearBtn = document.getElementById("tools-clear-search-btn");
  if (clearBtn) clearBtn.style.display = "none";
  renderToolsGrid();
}

/**
 * Returns array of FOSS tools covering a given attack ID
 */
function getFossToolsForAttack(attackId) {
  if (!attackId) return [];
  return FOSS_TOOLS_DATA.filter(tool => 
    tool.linkedAttacks.some(a => a.id === attackId)
  );
}

/**
 * Jumps to FOSS Tools mode and highlights a specific tool
 */
function jumpToFossTool(toolId) {
  if (typeof switchAppMode === "function") {
    switchAppMode("tools");
  }
  currentToolsFilter = "all";
  currentToolsSearch = "";
  renderToolsCategoryPills();
  renderToolsGrid();

  setTimeout(() => {
    const card = document.getElementById(`tool-${toolId}`);
    if (card) {
      card.scrollIntoView({ behavior: "smooth", block: "center" });
      card.classList.add("highlight-pulse");
      setTimeout(() => card.classList.remove("highlight-pulse"), 2500);
    }
  }, 100);
}

// Global exports
window.FOSS_TOOLS_DATA = FOSS_TOOLS_DATA;
window.renderToolsLayout = renderToolsLayout;
window.getFossToolsForAttack = getFossToolsForAttack;
window.jumpToFossTool = jumpToFossTool;
window.resetToolsFilters = resetToolsFilters;
