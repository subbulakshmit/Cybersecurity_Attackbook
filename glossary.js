/**
 * CYBER ATTACK BOOK - GLOSSARY & CYBER DEFENSE LEXICON
 * Comprehensive Alphabetical Dictionary (A–Z) of All Terms, Protocols, Attacks, and Defenses
 */

const GLOSSARY_DATA = [
  // =========================================================================
  // LETTER A
  // =========================================================================
  {
    letter: "A",
    term: "ACL (Access Control List)",
    acronym: "ACL",
    category: "Defenses & Controls",
    domainTag: "network",
    definition: "A sequential list of permit or deny rule statements applied to IP addresses, port numbers, and protocol types on network firewalls, routers, and switches to regulate ingress and egress traffic flows.",
    relevance: "Used in border firewalls to throttle volumetric SYN floods, enforce ingress filtering, and block unauthorized protocol traffic before reaching internal network buffers.",
    tags: ["Firewall", "Network", "Layer 3/4", "Defense"],
    reference: "IETF RFC 4987",
    appLinks: { mode: "learning", attackId: "dos" }
  },
  {
    letter: "A",
    term: "Active Directory (AD)",
    acronym: "AD",
    category: "Identity & AD",
    domainTag: "identity",
    definition: "Microsoft's proprietary enterprise directory service providing centralized domain identity management, Kerberos authentication, LDAP directory queries, and Group Policy object (GPO) administration across Windows networks.",
    relevance: "The primary target in enterprise ransomware campaigns; adversaries extract service tickets (Kerberoasting), abuse Pass-the-Hash, and compromise Domain Controllers to push malware cluster-wide.",
    tags: ["Microsoft", "Domain Controller", "Kerberos", "Enterprise"],
    reference: "MITRE ATT&CK T1087, T1484",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "A",
    term: "AES (Advanced Encryption Standard)",
    acronym: "AES",
    category: "Standards & Metrics",
    domainTag: "crypto",
    definition: "A symmetric block cipher standardized by NIST in 2001 (FIPS PUB 197) supporting key lengths of 128, 192, and 256 bits. Operates on 128-bit blocks using substitution-permutation network rounds.",
    relevance: "Enforced in Kerberos ticket exchange (AES-256) to eliminate crackable RC4 tokens, and utilized in WPA3-Enterprise Wi-Fi to protect data link frames against interception.",
    tags: ["Cryptography", "Symmetric Cipher", "FIPS 197", "Standard"],
    reference: "NIST FIPS 197",
    appLinks: { mode: "learning", attackId: "kerberoasting" }
  },
  {
    letter: "A",
    term: "Air-Gap",
    acronym: "Air-Gap",
    category: "Defenses & Controls",
    domainTag: "architecture",
    definition: "A physical security countermeasure ensuring that a computer network or system is physically, electrically, and logically isolated from unsecured external networks, including the public Internet.",
    relevance: "Employed in critical industrial infrastructure (SCADA Level 0-2) and immutable backup vaults to ensure ransomware or malware cannot bridge network interfaces.",
    tags: ["Physical Security", "Isolation", "SCADA", "Backups"],
    reference: "NIST SP 800-82",
    appLinks: { mode: "assessment", scenarioId: "sc_scada_grid" }
  },
  {
    letter: "A",
    term: "AiTM (Adversary-in-the-Middle)",
    acronym: "AiTM",
    category: "Attacks & Exploits",
    domainTag: "attack",
    definition: "An interception attack where the threat actor positions an automated reverse proxy between a target victim and a legitimate service (e.g. Microsoft 365), intercepting plaintext credentials and authenticated session cookies to bypass Multi-Factor Authentication (MFA).",
    relevance: "Featured in modern phishing campaigns and rogue AP captive portals where standard push notification or SMS MFA is proxied and stolen in real time.",
    tags: ["Phishing", "MFA Bypass", "Session Hijack", "Credential Access"],
    reference: "MITRE ATT&CK T1557",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },
  {
    letter: "A",
    term: "Amplification Attack",
    acronym: "Amplification",
    category: "Attacks & Exploits",
    domainTag: "network",
    definition: "A volumetric Distributed Denial of Service (DDoS) technique where an attacker sends small forged requests with a victim's spoofed source IP to public servers running stateless UDP protocols (DNS, NTP, SNMP), which reply with exponentially larger responses directed at the victim.",
    relevance: "DNS amplification leverages EDNS0 extensions to achieve 50x-70x bandwidth multiplication, overwhelming upstream ISP bandwidth and saturating border links.",
    tags: ["DDoS", "UDP", "DNS", "Bandwidth Saturation"],
    reference: "MITRE ATT&CK T1498.002",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "A",
    term: "Anycast",
    acronym: "Anycast",
    category: "Defenses & Controls",
    domainTag: "network",
    definition: "A network addressing and routing methodology in which a single destination IP address is simultaneously advertised by multiple geographically distributed physical nodes via BGP, routing client packets to the topologically nearest node.",
    relevance: "Core architectural defense for DDoS mitigation and global DNS servers; distributes massive packet floods across dozens of global scrubbing centers rather than overwhelming a single data center.",
    tags: ["BGP", "DDoS Mitigation", "Routing", "Architecture"],
    reference: "IETF RFC 4786",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "A",
    term: "API Gateway",
    acronym: "API GW",
    category: "Cloud & Container",
    domainTag: "cloud",
    definition: "A management layer positioned between client clients and backend microservices that acts as a single point of entry, handling request routing, API composition, rate limiting, authentication token validation, and protocol transformation.",
    relevance: "Central control point to neutralize Broken Object Level Authorization (BOLA) attacks by validating JWT scope claims against requested resource IDs prior to routing to backend containers.",
    tags: ["Microservices", "REST", "GraphQL", "Zero Trust"],
    reference: "OWASP API Security Top 10",
    appLinks: { mode: "assessment", scenarioId: "sc_cloud_breach" }
  },
  {
    letter: "A",
    term: "AppArmor",
    acronym: "AppArmor",
    category: "OS & Host",
    domainTag: "linux",
    definition: "A Linux Security Module (LSM) that provides Mandatory Access Control (MAC) based on program path names. Restricts programs to a limited set of files, capabilities, and network sockets defined in declarative profile files.",
    relevance: "Hardens Linux worker nodes and container runtimes, preventing compromised containerized processes from accessing host paths or raw socket primitives.",
    tags: ["Linux", "LSM", "Mandatory Access Control", "Hardening"],
    reference: "Linux Documentation / Documentation/security/apparmor.rst",
    appLinks: { mode: "assessment", scenarioId: "sc_kernel_escape" }
  },
  {
    letter: "A",
    term: "ARP Poisoning / Spoofing",
    acronym: "ARP Spoof",
    category: "Attacks & Exploits",
    domainTag: "network",
    definition: "A Layer-2 attack in local area networks where an adversary broadcasts forged Address Resolution Protocol replies, linking the adversary's MAC address with the IP address of a legitimate default gateway or server.",
    relevance: "Enables traffic interception, SSL stripping, and credential sniffing across unsegmented enterprise Ethernet switches without requiring upstream router compromise.",
    tags: ["Layer 2", "Local Network", "Ethernet", "MITM"],
    reference: "MITRE ATT&CK T1557.002",
    appLinks: { mode: "learning", attackId: "arp_poisoning" }
  },
  {
    letter: "A",
    term: "Autonomous System (AS)",
    acronym: "AS / ASN",
    category: "Network & Routing",
    domainTag: "network",
    definition: "A large network or group of networks under unified administrative control (such as an ISP, enterprise, or government) that shares a common routing policy with the rest of the global Internet, identified by an ASN.",
    relevance: "BGP route announcements occur between autonomous systems; unauthorized autonomous systems can hijack IP prefixes if cryptographic RPKI validation is absent.",
    tags: ["BGP", "Internet Infrastructure", "Routing", "Transit"],
    reference: "IETF RFC 1930",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },

  // =========================================================================
  // LETTER B
  // =========================================================================
  {
    letter: "B",
    term: "BGP (Border Gateway Protocol)",
    acronym: "BGP",
    category: "Network & Routing",
    domainTag: "network",
    definition: "The standardized exterior gateway routing protocol designed to exchange routing and reachability information among Autonomous Systems (AS) on the global Internet. Operates over TCP Port 179.",
    relevance: "Because original BGP lacked cryptographic origin verification, rogue routers can announce unauthorized IP blocks, enabling BGP prefix hijacking and large-scale traffic diversion.",
    tags: ["Core Routing", "Internet Protocol", "Layer 4", "TCP 179"],
    reference: "IETF RFC 4271",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "B",
    term: "BGP Prefix Hijacking",
    acronym: "BGP Hijack",
    category: "Attacks & Exploits",
    domainTag: "network",
    definition: "The illegitimate announcement of IP prefix blocks by a rogue Autonomous System that does not own or control those addresses, causing global internet traffic destined for the victim to route through the attacker's systems.",
    relevance: "Critical attack vector used for state-level financial espionage, cryptocurrency theft, and blackholing critical banking APIs during multi-vector extortion campaigns.",
    tags: ["Routing Poisoning", "Traffic Interception", "BGP", "Extortion"],
    reference: "MITRE ATT&CK T1584, T1557",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "B",
    term: "Blackholing (RTBH)",
    acronym: "RTBH",
    category: "Defenses & Controls",
    domainTag: "network",
    definition: "Remotely Triggered Black Hole routing is a network defense mechanism that instructs upstream ISP transit routers to drop all incoming packets directed at a targeted IP address into a null interface (`Null0`).",
    relevance: "Emergency last-resort defense during catastrophic DDoS floods that protects remaining enterprise infrastructure, though it causes intentional collateral downtime for the targeted service.",
    tags: ["DDoS", "Routing", "ISP", "Mitigation"],
    reference: "IETF RFC 3882",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "B",
    term: "BloodHound",
    acronym: "BloodHound",
    category: "Identity & AD",
    domainTag: "identity",
    definition: "A graphical Active Directory relationship mapping tool that uses graph theory to reveal hidden, complex, and unintended attack paths and permission chains leading to Domain Admin compromise.",
    relevance: "Employed by red teamers and ransomware operators during post-exploitation reconnaissance to find minimal-hop escalation routes via nested group memberships and ACL permissions.",
    tags: ["Active Directory", "Reconnaissance", "Graph Theory", "Privilege Escalation"],
    reference: "MITRE ATT&CK T1087, T1069",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "B",
    term: "BOLA (Broken Object Level Authorization)",
    acronym: "BOLA",
    category: "Attacks & Exploits",
    domainTag: "appsec",
    definition: "The #1 flaw on the OWASP API Security Top 10 (formerly IDOR), where an API endpoint accepts an arbitrary user-supplied object identifier in requests without verifying that the client holds legitimate ownership permissions for that specific resource.",
    relevance: "Allows adversaries to scrape hundreds of thousands of customer profiles, bank statements, or patient records simply by iterating numerical or UUID object IDs in REST requests.",
    tags: ["API Security", "OWASP API1", "Access Control", "Data Leak"],
    reference: "OWASP API Security Top 10 (API1:2023)",
    appLinks: { mode: "assessment", scenarioId: "sc_cloud_breach" }
  },
  {
    letter: "B",
    term: "Buffer Overflow",
    acronym: "BOF",
    category: "Attacks & Exploits",
    domainTag: "os",
    definition: "An anomaly where a program, while writing data to a memory buffer, overruns the allocated buffer's boundary and overwrites adjacent memory locations, potentially corrupting control flow registers (e.g. Instruction Pointer EIP/RIP).",
    relevance: "A fundamental binary exploitation technique used against C/C++ services to achieve arbitrary remote code execution on operating systems and embedded firmware.",
    tags: ["Memory Corruption", "C/C++", "RCE", "Binary Exploitation"],
    reference: "MITRE ATT&CK T1203, CWE-119",
    appLinks: { mode: "learning", attackId: "buffer_overflow" }
  },
  {
    letter: "B",
    term: "BYOVD (Bring Your Own Vulnerable Driver)",
    acronym: "BYOVD",
    category: "Attacks & Exploits",
    domainTag: "os",
    definition: "An evasion technique in which adversaries with local administrative privileges install a legitimate, cryptographically signed third-party kernel driver known to contain vulnerabilities, and exploit it to execute arbitrary Ring-0 kernel code.",
    relevance: "Used by advanced ransomware operators (e.g. BlackCat) to bypass Windows Driver Signature Enforcement (DSE) and disable EDR kernel hooks and process monitors directly from Ring 0.",
    tags: ["Kernel", "Ring 0", "Defense Evasion", "EDR Bypass"],
    reference: "MITRE ATT&CK T1068, T1562.001",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },

  // =========================================================================
  // LETTER C
  // =========================================================================
  {
    letter: "C",
    term: "Captive Portal",
    acronym: "Captive Portal",
    category: "Network & Routing",
    domainTag: "wireless",
    definition: "A web page displayed to newly connected network clients before granting full internet access, requiring user authentication, terms acceptance, or payment verification.",
    relevance: "Weaponized by rogue AP operators (Evil Twin attacks) to spoof enterprise SSO login pages and capture corporate email credentials and MFA session tokens.",
    tags: ["Wi-Fi", "Authentication", "Phishing", "Layer 2"],
    reference: "MITRE ATT&CK T1566.002",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },
  {
    letter: "C",
    term: "Certificate Pinning",
    acronym: "Pinning",
    category: "Defenses & Controls",
    domainTag: "crypto",
    definition: "The security process of hardcoding the expected X.509 certificate public key hash directly inside a client application, rejecting connections to any server presenting a different certificate even if signed by a trusted root CA.",
    relevance: "Prevents adversaries and rogue proxy servers from using forged intermediate certificates or rogue Wi-Fi captive portals to intercept encrypted HTTPS and API traffic.",
    tags: ["TLS", "Public Key", "AppSec", "MITM Defense"],
    reference: "OWASP Certificate and Public Key Pinning",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },
  {
    letter: "C",
    term: "ChaCha20",
    acronym: "ChaCha20",
    category: "Standards & Metrics",
    domainTag: "crypto",
    definition: "A modern, high-speed stream cipher developed by Daniel J. Bernstein that operates on 512-bit state words through 20 rounds of quarter-round operations. Often paired with Poly1305 for authenticated encryption (AEAD).",
    relevance: "Widely selected by modern human-operated ransomware groups (such as BlackCat/ALPHV) because it encrypts files significantly faster than AES on systems lacking hardware AES-NI instructions.",
    tags: ["Stream Cipher", "Ransomware", "Cryptography", "RFC 7539"],
    reference: "IETF RFC 7539",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "C",
    term: "Credential Guard",
    acronym: "Cred Guard",
    category: "Defenses & Controls",
    domainTag: "os",
    definition: "A Windows security feature introduced in Windows 10/Server 2016 that uses Virtualization-Based Security (VBS) and Hyper-V to run the Local Security Authority (LSA) in an isolated virtual container (Virtual Secure Mode).",
    relevance: "Prevents tools like Mimikatz from extracting NTLM password hashes and Kerberos TGT tickets from LSASS memory, even if the attacker has gained local SYSTEM administrator privileges.",
    tags: ["Windows", "VBS", "Mimikatz Defense", "Endpoint Security"],
    reference: "Microsoft Learn / Windows Security / Credential Guard",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "C",
    term: "CVSS (Common Vulnerability Scoring System)",
    acronym: "CVSS",
    category: "Standards & Metrics",
    domainTag: "metrics",
    definition: "An open industry standard specification maintained by FIRST for calculating the technical severity and characteristic metrics of software and hardware vulnerabilities on a numerical scale from 0.0 to 10.0.",
    relevance: "Used across all 68 threat dossiers in this application to rate threat severity (Low: 0.1–3.9, Medium: 4.0–6.9, High: 7.0–8.9, Critical: 9.0–10.0).",
    tags: ["Vulnerability Assessment", "Metrics", "FIRST", "Risk"],
    reference: "FIRST CVSS v3.1 / v4.0 Specification",
    appLinks: { mode: "learning", attackId: "dos" }
  },

  // =========================================================================
  // LETTER D
  // =========================================================================
  {
    letter: "D",
    term: "Data Diode",
    acronym: "Data Diode",
    category: "Defenses & Controls",
    domainTag: "hardware",
    definition: "A unidirectional hardware network appliance utilizing physical LED transmitters and photodiode receivers that physically enforces one-way data communication, making reverse packet transmission physically impossible.",
    relevance: "Essential hardware isolation control in industrial power grids and nuclear facilities to allow telemetry export from SCADA Level 2/3 to corporate IT without opening an ingress attack vector.",
    tags: ["Physical Security", "SCADA", "Hardware", "Air-Gap Alternative"],
    reference: "NIST SP 800-82r3",
    appLinks: { mode: "assessment", scenarioId: "sc_scada_grid" }
  },
  {
    letter: "D",
    term: "Deauthentication Attack",
    acronym: "Deauth Attack",
    category: "Attacks & Exploits",
    domainTag: "wireless",
    definition: "A denial-of-service attack targeting 802.11 wireless networks by transmitting spoofed management frames (Type 0, Subtype 12) bearing the AP's MAC address, forcibly disconnecting authenticated Wi-Fi clients.",
    relevance: "Used by wireless attackers to sever connections with genuine access points and drive unsuspecting client devices onto rogue Evil Twin access points.",
    tags: ["Wi-Fi", "802.11", "Layer 2", "Rogue AP"],
    reference: "IEEE 802.11 Standard",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },
  {
    letter: "D",
    term: "DEFCON",
    acronym: "DEFCON",
    category: "Standards & Metrics",
    domainTag: "soc",
    definition: "Defense Readiness Condition; a subsystem of alert postures used to dictate readiness levels from DEFCON 5 (normal peacetime) to DEFCON 1 (maximum operational readiness / imminent critical threat).",
    relevance: "Used in the top navigation live indicator bar of this application to reflect active SOC alert and incident simulation escalation levels.",
    tags: ["SOC", "Incident Management", "Alert Posture", "Readiness"],
    reference: "US Joint Chiefs of Staff JCS Pub 527",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "D",
    term: "Defense-in-Depth",
    acronym: "DiD",
    category: "Defenses & Controls",
    domainTag: "architecture",
    definition: "A foundational information assurance strategy incorporating multiple redundant defensive layers (Perimeter, Network, Host, Identity, Application, Data) so that if one security barrier is breached, subsequent layers prevent total compromise.",
    relevance: "Directly measured in the Assessment Mode scorecard, rewarding security strategies that blend network, host, and application controls rather than relying solely on firewalls.",
    tags: ["Security Architecture", "Layered Defense", "Strategy", "Audit"],
    reference: "NSA Defense in Depth Methodology",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "D",
    term: "Dirty Pipe (CVE-2022-0847)",
    acronym: "Dirty Pipe",
    category: "Attacks & Exploits",
    domainTag: "linux",
    definition: "A high-severity vulnerability in Linux kernels 5.8+ caused by uninitialized flags in pipe buffer data structures, allowing unprivileged local users to overwrite data in arbitrary read-only page cache files.",
    relevance: "Enables unprivileged container users to overwrite read-only files (such as `/etc/passwd` or setuid binaries) on the underlying host, executing an immediate container escape to host root.",
    tags: ["Linux Kernel", "CVE-2022-0847", "Container Escape", "Privilege Escalation"],
    reference: "CVE-2022-0847 / NVD",
    appLinks: { mode: "assessment", scenarioId: "sc_kernel_escape" }
  },
  {
    letter: "D",
    term: "DLP (Data Loss Prevention)",
    acronym: "DLP",
    category: "Defenses & Controls",
    domainTag: "data",
    definition: "A suite of technologies and organizational policies designed to detect, monitor, and block sensitive enterprise data (PII, financial records, intellectual property) from being exfiltrated beyond corporate perimeters.",
    relevance: "Deploys automated S3 bucket circuit breakers and anomaly alerts that instantly revoke compromised IAM role credentials when bulk egress volume exceeds normal baseline thresholds.",
    tags: ["Data Security", "Compliance", "Exfiltration Defense", "Cloud"],
    reference: "NIST SP 800-53 (System and Information Integrity)",
    appLinks: { mode: "assessment", scenarioId: "sc_cloud_breach" }
  },
  {
    letter: "D",
    term: "DNP3 (Distributed Network Protocol)",
    acronym: "DNP3",
    category: "ICS & SCADA",
    domainTag: "scada",
    definition: "A set of communications protocols used between components in process automation systems, widely deployed in electric power utilities, water management systems, and substation telemetry.",
    relevance: "Like Modbus, legacy DNP3 implementations lack cryptographic authentication, enabling unauthenticated command injection when network segmentation between IT and OT breaks down.",
    tags: ["SCADA", "Industrial Protocol", "Smart Grid", "Purdue Model"],
    reference: "IEEE Std 1815-2012",
    appLinks: { mode: "assessment", scenarioId: "sc_scada_grid" }
  },
  {
    letter: "D",
    term: "DNS Amplification",
    acronym: "DNS Amp",
    category: "Attacks & Exploits",
    domainTag: "network",
    definition: "A form of distributed reflective denial-of-service attack where an adversary transmits spoofed DNS lookup queries requesting large response records (such as `ANY` or `TXT` with EDNS0) to open public resolvers, swamping the victim's network.",
    relevance: "Produces massive multi-hundred gigabit volumetric packet floods capable of exhausting transit pipe bandwidth before firewalls can inspect packets.",
    tags: ["DDoS", "DNS", "Reflective Attack", "UDP"],
    reference: "MITRE ATT&CK T1498.002",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "D",
    term: "Docker Socket (`/var/run/docker.sock`)",
    acronym: "Docker Socket",
    category: "Cloud & Container",
    domainTag: "cloud",
    definition: "The primary UNIX IPC socket used by the Docker daemon to accept CLI commands and REST API requests for managing containers, images, volumes, and networks.",
    relevance: "Mounting `/var/run/docker.sock` inside an untrusted user container grants that container full root administrative control over the host Docker daemon, allowing instant container escape.",
    tags: ["Docker", "Kubernetes", "Container Security", "Escape"],
    reference: "MITRE ATT&CK T1611",
    appLinks: { mode: "assessment", scenarioId: "sc_kernel_escape" }
  },
  {
    letter: "D",
    term: "Domain Admin (DA)",
    acronym: "DA",
    category: "Identity & AD",
    domainTag: "identity",
    definition: "A high-privilege built-in security group in Microsoft Active Directory whose members possess administrative authority across all domain controllers, member servers, and directory objects in the domain.",
    relevance: "The ultimate objective of ransomware syndicates; once Domain Admin credentials are stolen via Kerberoasting or LSASS dumping, the adversary can distribute ransomware enterprise-wide.",
    tags: ["Active Directory", "Privilege", "Identity", "Crown Jewels"],
    reference: "Microsoft Learn / Active Directory Security Groups",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "D",
    term: "DoS / DDoS",
    acronym: "DoS / DDoS",
    category: "Attacks & Exploits",
    domainTag: "network",
    definition: "Denial of Service (DoS) and Distributed Denial of Service (DDoS) are cyberattacks intended to make a machine, network resource, or web application unavailable to its legitimate users by exhausting system resources or bandwidth.",
    relevance: "Threat Vector #1 in this application; encompasses Layer 4 transport floods (SYN, UDP) and Layer 7 application exhaustion attacks (Slowloris, HTTP floods).",
    tags: ["Availability", "SYN Flood", "Slowloris", "DDoS"],
    reference: "MITRE ATT&CK T1498, T1499",
    appLinks: { mode: "learning", attackId: "dos" }
  },
  {
    letter: "D",
    term: "DPI (Deep Packet Inspection)",
    acronym: "DPI",
    category: "Defenses & Controls",
    domainTag: "network",
    definition: "An advanced network packet filtering method that examines the actual data payload of network packets as they pass through an inspection checkpoint, rather than solely checking packet headers.",
    relevance: "Essential in industrial SCADA firewalls to inspect Modbus and DNP3 function codes, allowing read-only diagnostic telemetry while blocking unauthorized command write requests.",
    tags: ["Firewall", "Inspection", "Payload Analysis", "SCADA"],
    reference: "NIST SP 800-82",
    appLinks: { mode: "assessment", scenarioId: "sc_scada_grid" }
  },

  // =========================================================================
  // LETTER E
  // =========================================================================
  {
    letter: "E",
    term: "EAP-TLS",
    acronym: "EAP-TLS",
    category: "Defenses & Controls",
    domainTag: "wireless",
    definition: "Extensible Authentication Protocol - Transport Layer Security (RFC 5216); the gold-standard 802.1X wireless authentication framework that enforces mutual cryptographic verification using X.509 client and server certificates.",
    relevance: "Completely neutralizes rogue access point (Evil Twin) attacks because corporate client devices will reject associating with any access point lacking a certificate signed by the corporate private CA.",
    tags: ["802.1X", "Wi-Fi", "PKI", "Mutual TLS"],
    reference: "IETF RFC 5216",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },
  {
    letter: "E",
    term: "eBPF (Extended Berkeley Packet Filter)",
    acronym: "eBPF",
    category: "OS & Host",
    domainTag: "linux",
    definition: "A revolutionary Linux kernel technology that allows sandboxed, verified bytecode programs to run directly inside the kernel in response to tracepoints, system calls, and network events without changing kernel source code.",
    relevance: "Powers cloud-native runtime security monitors like Falco, enabling real-time detection and millisecond-level automated process termination for unauthorized shell spawning or container breakouts.",
    tags: ["Linux Kernel", "Runtime Security", "Tracing", "Cloud Native"],
    reference: "eBPF Foundation / ebpf.io",
    appLinks: { mode: "assessment", scenarioId: "sc_kernel_escape" }
  },
  {
    letter: "E",
    term: "EDR (Endpoint Detection and Response)",
    acronym: "EDR",
    category: "Defenses & Controls",
    domainTag: "endpoint",
    definition: "An enterprise endpoint security solution that continuously records host system activities (process lineage, memory modifications, network connections) and applies behavioral analytics to detect, isolate, and remediate advanced threats.",
    relevance: "Crucial countermeasure against ransomware lateral movement; capable of automatically containing an infected workstation via API commands within seconds of suspicious PowerShell executions.",
    tags: ["Endpoint", "SOC", "Containment", "Behavioral Analysis"],
    reference: "Gartner EDR Research",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "E",
    term: "EDNS0 (Extension Mechanisms for DNS)",
    acronym: "EDNS0",
    category: "Network & Routing",
    domainTag: "network",
    definition: "An extension to the original Domain Name System protocol (RFC 6891) that allows DNS clients to advertise larger UDP buffer packet sizes (up to 4,096 bytes) rather than the historic 512-byte limit.",
    relevance: "Frequently weaponized by attackers in DNS amplification attacks to receive 4KB responses for a 60-byte request, maximizing bandwidth amplification factors.",
    tags: ["DNS", "UDP", "Amplification", "IETF"],
    reference: "IETF RFC 6891",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "E",
    term: "Evil Twin",
    acronym: "Evil Twin",
    category: "Attacks & Exploits",
    domainTag: "wireless",
    definition: "A fraudulent, rogue wireless access point that masquerades as a legitimate network by spoofing its SSID and MAC address, tricking nearby laptops and mobile devices into connecting.",
    relevance: "Threat Vector #45 in this application; enables rogue operators to intercept network communications, steal single sign-on tokens, and execute credential harvesting via captive portals.",
    tags: ["Wi-Fi", "Spoofing", "Rogue AP", "Credential Theft"],
    reference: "MITRE ATT&CK T1040, T1557",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },

  // =========================================================================
  // LETTER F
  // =========================================================================
  {
    letter: "F",
    term: "Falco",
    acronym: "Falco",
    category: "Defenses & Controls",
    domainTag: "cloud",
    definition: "An open-source cloud-native runtime security tool originally developed by Sysdig and hosted by the CNCF that uses eBPF to detect anomalous application behaviors, unexpected shell spawns, and container privilege escalations.",
    relevance: "Deployed on Kubernetes worker nodes to detect and kill container breakout attempts (such as Dirty Pipe exploitation or Docker socket queries) in real time.",
    tags: ["CNCF", "eBPF", "Kubernetes", "Runtime Detection"],
    reference: "CNCF Falco Project / falco.org",
    appLinks: { mode: "assessment", scenarioId: "sc_kernel_escape" }
  },
  {
    letter: "F",
    term: "Format String Vulnerability",
    acronym: "Format String",
    category: "Attacks & Exploits",
    domainTag: "os",
    definition: "A software vulnerability occurring when user-supplied input is directly passed as the format string argument to formatted I/O functions like `printf()`, `sprintf()`, or `syslog()` without a static format specifier.",
    relevance: "Threat Vector #83 in this application; allows adversaries to leak stack memory (`%x`, `%s`) or write arbitrary values to arbitrary memory locations using `%n` specifiers.",
    tags: ["C/C++", "Memory Corruption", "Binary Exploitation", "CWE-134"],
    reference: "CWE-134: Use of Externally-Controlled Format String",
    appLinks: { mode: "learning", attackId: "dos" }
  },

  // =========================================================================
  // LETTER G
  // =========================================================================
  {
    letter: "G",
    term: "gMSA (Group Managed Service Accounts)",
    acronym: "gMSA",
    category: "Identity & AD",
    domainTag: "identity",
    definition: "An Active Directory account configuration providing automated, centralized password management, complex 128-character rotating passwords, and delegated SPN management across multiple server hosts.",
    relevance: "Eliminates Kerberoasting vulnerabilities by removing human-generated, easily crackable passwords from SQL, IIS, and application service accounts.",
    tags: ["Active Directory", "Kerberoasting Defense", "Identity", "Hardening"],
    reference: "Microsoft Learn / Group Managed Service Accounts",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "G",
    term: "GRE Tunnel (Generic Routing Encapsulation)",
    acronym: "GRE",
    category: "Network & Routing",
    domainTag: "network",
    definition: "A tunneling protocol developed by Cisco (RFC 2784) that encapsulates a wide variety of network layer protocols inside virtual point-to-point links over an Internet Protocol network.",
    relevance: "Used by cloud DDoS scrubbing centers (e.g. Magic Transit) to forward clean, de-duplicated traffic back to origin enterprise data centers after filtering volumetric packet floods.",
    tags: ["Tunneling", "Layer 3", "DDoS Scrubbing", "Perimeter"],
    reference: "IETF RFC 2784",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "G",
    term: "gVisor",
    acronym: "gVisor",
    category: "Cloud & Container",
    domainTag: "cloud",
    definition: "An open-source user-space container runtime sandbox created by Google that implements a virtualized Linux kernel (`runsc`), intercepting application system calls and preventing containers from directly touching the host Linux kernel.",
    relevance: "Prevents container escape vulnerabilities (including kernel privilege escalations like Dirty Pipe) by ensuring exploit payloads run within an unprivileged user-space emulation layer.",
    tags: ["Container Sandbox", "Kubernetes", "Kernel Isolation", "Google Cloud"],
    reference: "Google Open Source / gvisor.dev",
    appLinks: { mode: "assessment", scenarioId: "sc_kernel_escape" }
  },

  // =========================================================================
  // LETTER H
  // =========================================================================
  {
    letter: "H",
    term: "Honeypot / Canary",
    acronym: "Honeypot",
    category: "Defenses & Controls",
    domainTag: "soc",
    definition: "A decoy asset, file, or account deployed inside an enterprise environment with no legitimate operational purpose, specifically configured to trigger high-confidence alerts when interacted with by unauthorized intruders.",
    relevance: "Ransomware canary files planted in file shares automatically trigger process kill drivers when modified, halting mass encryption in its earliest stages.",
    tags: ["Deception Technology", "Early Warning", "Detection", "Canary"],
    reference: "MITRE D3FEND / D3-HNT",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "H",
    term: "HSTS (HTTP Strict Transport Security)",
    acronym: "HSTS",
    category: "Defenses & Controls",
    domainTag: "appsec",
    definition: "A web security policy mechanism transmitted via response header (`Strict-Transport-Security`) that instructs compliant web browsers to interact with the domain exclusively over secure HTTPS connections, refusing any HTTP fallback.",
    relevance: "Neutralizes SSL stripping attacks conducted by rogue APs by preventing the browser from ever issuing unencrypted HTTP requests.",
    tags: ["Web Security", "HTTPS", "Browser Security", "RFC 6797"],
    reference: "IETF RFC 6797",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },

  // =========================================================================
  // LETTER I
  // =========================================================================
  {
    letter: "I",
    term: "IAM (Identity and Access Management)",
    acronym: "IAM",
    category: "Identity & AD",
    domainTag: "cloud",
    definition: "The overarching security discipline and software framework enabling organizations to manage electronic identities, control user and service access, and enforce principle of least privilege across computing resources.",
    relevance: "In cloud environments, over-permissioned IAM roles (such as wildcard `s3:*`) enable catastrophic data exfiltration when metadata services (IMDS) are breached via SSRF.",
    tags: ["Cloud Security", "Least Privilege", "RBAC", "Access Control"],
    reference: "NIST SP 800-63",
    appLinks: { mode: "assessment", scenarioId: "sc_cloud_breach" }
  },
  {
    letter: "I",
    term: "ICS (Industrial Control Systems)",
    acronym: "ICS",
    category: "ICS & SCADA",
    domainTag: "scada",
    definition: "A broad term describing instrumentation, control systems, and associated software utilized to monitor and operate industrial processes across utilities, manufacturing, power generation, and transportation.",
    relevance: "Critical infrastructure domain featured in Scenario 4, where OT protocols lack modern cryptographic controls and rely on strict physical and network segmentation.",
    tags: ["SCADA", "Operational Technology", "Critical Infrastructure", "PLCs"],
    reference: "NIST SP 800-82",
    appLinks: { mode: "assessment", scenarioId: "sc_scada_grid" }
  },
  {
    letter: "I",
    term: "IMDS (Instance Metadata Service)",
    acronym: "IMDS",
    category: "Cloud & Container",
    domainTag: "cloud",
    definition: "An internal, link-local HTTP service hosted at IP address `169.254.169.254` by cloud platforms (AWS, GCP, Azure) that provides virtual machine instances with runtime metadata, user-data, and temporary IAM STS security credentials.",
    relevance: "Targeted in cloud SSRF vulnerabilities; IMDSv1 permits unauthenticated GET requests, while IMDSv2 enforces session token headers and hop limits to block SSRF proxying.",
    tags: ["AWS", "Cloud Credentials", "SSRF", "Metadata"],
    reference: "AWS EC2 IMDSv2 Documentation",
    appLinks: { mode: "assessment", scenarioId: "sc_cloud_breach" }
  },
  {
    letter: "I",
    term: "Immutable Backup (WORM)",
    acronym: "WORM Storage",
    category: "Defenses & Controls",
    domainTag: "data",
    definition: "Data storage technology (Write-Once-Read-Many) and snapshot policies where written backup records cannot be modified, encrypted, or deleted by any user or administrator for a predefined retention timeframe.",
    relevance: "The definitive defensive countermeasure against ransomware extortion; guarantees rapid system restoration even if domain controllers and Active Directory are totally compromised.",
    tags: ["Backups", "Ransomware Defense", "Resilience", "WORM"],
    reference: "NIST SP 800-209",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "I",
    term: "Ingress uRPF (Unicast Reverse Path Forwarding)",
    acronym: "uRPF",
    category: "Defenses & Controls",
    domainTag: "network",
    definition: "A router security feature (RFC 3704) that verifies whether the source IP address of an incoming packet has a matching route in the router's Forwarding Information Base (FIB), dropping spoofed packets.",
    relevance: "Essential perimeter defense to prevent adversaries from generating spoofed-source DNS and UDP amplification attacks from inside or through transit networks.",
    tags: ["Anti-Spoofing", "Routing", "Perimeter", "RFC 3704"],
    reference: "IETF RFC 3704 / BCP 84",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "I",
    term: "IoT (Internet of Things)",
    acronym: "IoT",
    category: "Network & Routing",
    domainTag: "iot",
    definition: "A network of physical devices, sensors, appliances, and embedded hardware connected to the Internet, frequently characterized by limited computational resources and default or hardcoded credentials.",
    relevance: "Threat Vectors #60-64 in this application; commonly recruited by automated botnets (e.g. Mirai) to launch record-breaking volumetric DDoS floods.",
    tags: ["Embedded Systems", "Botnets", "Mirai", "DDoS"],
    reference: "NIST SP 800-213",
    appLinks: { mode: "learning", attackId: "dos" }
  },

  // =========================================================================
  // LETTER K
  // =========================================================================
  {
    letter: "K",
    term: "Kerberoasting",
    acronym: "Kerberoasting",
    category: "Attacks & Exploits",
    domainTag: "identity",
    definition: "A post-exploitation credential access technique targeting Active Directory service accounts registered with Service Principal Names (SPNs). Attackers request Kerberos TGS tickets and crack the password hashes offline.",
    relevance: "Enables any valid domain user account to extract and offline brute-force the plaintext passwords of high-privileged SQL, IIS, or administrative service accounts.",
    tags: ["Active Directory", "Kerberos", "Credential Access", "Offline Cracking"],
    reference: "MITRE ATT&CK T1558.003",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "K",
    term: "Kill Chain (Cyber Kill Chain)",
    acronym: "Kill Chain",
    category: "Standards & Metrics",
    domainTag: "metrics",
    definition: "A threat modeling framework originally developed by Lockheed Martin identifying the sequential stages of an advanced cyberattack: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control (C2), Actions on Objectives.",
    relevance: "Each of the 68 threat vectors in Learning Mode and the 6 scenarios in Assessment Mode features a multi-stage operational kill chain breakdown.",
    tags: ["Threat Modeling", "Adversary TTPs", "Methodology", "Lockheed Martin"],
    reference: "Lockheed Martin Cyber Kill Chain Framework",
    appLinks: { mode: "learning", attackId: "dos" }
  },
  {
    letter: "K",
    term: "Kubernetes (K8s)",
    acronym: "K8s",
    category: "Cloud & Container",
    domainTag: "cloud",
    definition: "An open-source container orchestration platform for automating application container deployment, scaling, and operational lifecycle management across clustered environments.",
    relevance: "Focus of Scenario 6; vulnerabilities in pod configurations, mounted Docker sockets, or the underlying Linux host kernel can result in total cluster takeover.",
    tags: ["Container Orchestration", "Cloud Native", "Pods", "Nodes"],
    reference: "Cloud Native Computing Foundation (CNCF)",
    appLinks: { mode: "assessment", scenarioId: "sc_kernel_escape" }
  },

  // =========================================================================
  // LETTER L
  // =========================================================================
  {
    letter: "L",
    term: "LAPS (Local Administrator Password Solution)",
    acronym: "LAPS",
    category: "Defenses & Controls",
    domainTag: "identity",
    definition: "A Microsoft solution that automatically generates, randomizes, and stores unique, complex passwords for the local administrator account on each domain-joined Windows endpoint in Active Directory or Azure AD.",
    relevance: "Completely neutralizes Pass-the-Hash and lateral movement because local administrator passwords are no longer shared across workstations.",
    tags: ["Active Directory", "Password Management", "Pass-the-Hash Defense", "Windows"],
    reference: "Microsoft Learn / Windows LAPS",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "L",
    term: "Lateral Movement",
    acronym: "Lateral Move",
    category: "Attacks & Exploits",
    domainTag: "attack",
    definition: "Techniques cyber adversaries employ following initial access to extend their access to additional systems, servers, and sensitive endpoints across a victim organization's internal network.",
    relevance: "Includes Pass-the-Hash over SMB, WMI execution, and RDP hijacking; central phase in enterprise ransomware before deploying the payload cluster-wide.",
    tags: ["Post-Exploitation", "SMB", "WMI", "Enterprise"],
    reference: "MITRE ATT&CK Tactic TA0008",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "L",
    term: "LSASS (Local Security Authority Subsystem Service)",
    acronym: "LSASS",
    category: "OS & Host",
    domainTag: "os",
    definition: "The core Windows operating system process (`lsass.exe`) responsible for enforcing security policies, managing user authentication, verifying login credentials, and caching Kerberos/NTLM tokens in memory.",
    relevance: "Prime target for credential dumping tools like Mimikatz; dumping LSASS process memory yields plaintext credentials and authentication hashes.",
    tags: ["Windows", "Credential Access", "Mimikatz", "Security Subsystem"],
    reference: "MITRE ATT&CK T1003.001",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },

  // =========================================================================
  // LETTER M
  // =========================================================================
  {
    letter: "M",
    term: "MAC Address (Media Access Control)",
    acronym: "MAC",
    category: "Network & Routing",
    domainTag: "network",
    definition: "A unique 48-bit hardware identifier permanently assigned to a Network Interface Card (NIC) for communicating over physical data link layers (Layer 2) of local networks.",
    relevance: "Used in ARP poisoning, Wi-Fi deauth floods, and Evil Twin attacks; spoofing legitimate MAC addresses allows adversaries to bypass basic network access filters.",
    tags: ["Layer 2", "Hardware Identifier", "Ethernet", "Wi-Fi"],
    reference: "IEEE 802 Standards",
    appLinks: { mode: "learning", attackId: "dos" }
  },
  {
    letter: "M",
    term: "Mimikatz",
    acronym: "Mimikatz",
    category: "Attacks & Exploits",
    domainTag: "attack",
    definition: "A widely utilized post-exploitation tool created by Benjamin Delpy that extracts plaintext passwords, NTLM hashes, PIN codes, and Kerberos tickets from memory by reading the LSASS process.",
    relevance: "Frequently integrated into ransomware automation scripts to instantly harvest Domain Admin credentials once a single privileged host is compromised.",
    tags: ["Credential Dumping", "Post-Exploitation", "LSASS", "Red Team"],
    reference: "MITRE ATT&CK T1003.001",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "M",
    term: "MITRE ATT&CK",
    acronym: "ATT&CK",
    category: "Standards & Metrics",
    domainTag: "metrics",
    definition: "A globally accessible curated knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world incident observations, maintained by the MITRE Corporation.",
    relevance: "Every attack vector and scenario in this application is mapped directly to authoritative MITRE ATT&CK techniques (e.g. T1498, T1003, T1190, T1557).",
    tags: ["Framework", "TTPs", "Threat Intelligence", "Standard"],
    reference: "MITRE ATT&CK / attack.mitre.org",
    appLinks: { mode: "learning", attackId: "dos" }
  },
  {
    letter: "M",
    term: "Modbus / Modbus TCP",
    acronym: "Modbus",
    category: "ICS & SCADA",
    domainTag: "scada",
    definition: "A de facto standard industrial serial and Ethernet protocol published in 1979 for communicating with Programmable Logic Controllers (PLCs). Operates over TCP Port 502 with no built-in authentication.",
    relevance: "Focus of Scenario 4; attackers forge Function Code 05 (Write Single Coil) commands to trip electrical substation breakers and disrupt industrial facilities.",
    tags: ["SCADA", "Industrial Protocol", "TCP 502", "Unauthenticated"],
    reference: "Modbus Organization Specification",
    appLinks: { mode: "assessment", scenarioId: "sc_scada_grid" }
  },

  // =========================================================================
  // LETTER P
  // =========================================================================
  {
    letter: "P",
    term: "Pass-the-Hash (PtH)",
    acronym: "PtH",
    category: "Attacks & Exploits",
    domainTag: "identity",
    definition: "An authentication exploit technique in which an attacker captures an NTLM password hash from memory or the SAM database and uses it directly to authenticate to remote servers over SMB or WMI without needing to crack the plaintext password.",
    relevance: "Primary propagation mechanism used by enterprise ransomware (WannaCry, NotPetya, BlackCat) to move laterally across enterprise networks.",
    tags: ["Active Directory", "NTLM", "Lateral Movement", "Credential Theft"],
    reference: "MITRE ATT&CK T1550.002",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "P",
    term: "PLC (Programmable Logic Controller)",
    acronym: "PLC",
    category: "ICS & SCADA",
    domainTag: "scada",
    definition: "A ruggedized industrial digital computer adapted for control of manufacturing processes, power distribution, water treatment plants, and robotic assemblies under harsh physical conditions.",
    relevance: "Targeted in advanced OT cyber warfare attacks (e.g. Stuxnet, Industroyer); adversaries attempt to overwrite ladder logic or flash malicious firmware to cause physical equipment damage.",
    tags: ["Industrial Hardware", "SCADA", "Ladder Logic", "Purdue Level 1"],
    reference: "IEC 61131 Standard",
    appLinks: { mode: "assessment", scenarioId: "sc_scada_grid" }
  },
  {
    letter: "P",
    term: "PMF (Protected Management Frames - 802.11w)",
    acronym: "802.11w PMF",
    category: "Defenses & Controls",
    domainTag: "wireless",
    definition: "An amendment to the IEEE 802.11 wireless standard (802.11w) that provides cryptographic integrity, replay protection, and origin authenticity to management frames such as deauthentication, disassociation, and robust action frames.",
    relevance: "Mandatory countermeasure that completely stops wireless deauthentication floods, preventing attackers from kicking users off legitimate Wi-Fi access points.",
    tags: ["802.11w", "Wi-Fi", "Cryptographic Protection", "Deauth Defense"],
    reference: "IEEE 802.11w-2009",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },
  {
    letter: "P",
    term: "Proof-of-Work (PoW)",
    acronym: "PoW",
    category: "Defenses & Controls",
    domainTag: "appsec",
    definition: "A cryptographic challenge issued by a web server requiring a client computer to expend measurable computational effort (e.g. solving a partial hash collision) before the server processes expensive API requests.",
    relevance: "Deployed via adaptive WAFs to defeat automated credential stuffing, bot scraping, and application Layer-7 DDoS floods without degrading the experience of human users.",
    tags: ["Bot Defense", "Application Security", "WAF", "Cryptography"],
    reference: "Cloudflare Turnstile / Proof of Work Bot Defenses",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "P",
    term: "Purdue Model",
    acronym: "Purdue",
    category: "Standards & Metrics",
    domainTag: "scada",
    definition: "An enterprise reference architecture for Industrial Control Systems (ICS) segmenting operations into distinct logical security zones: Level 0 (Physical Process), Level 1 (Sensing/PLCs), Level 2 (Control Systems/HMIs), Level 3 (Site Operations), Level 4/5 (Corporate IT/Enterprise).",
    relevance: "Strict adherence to the Purdue Model with hardware data diodes prevents cyberattacks in the corporate IT network (Level 4) from pivoting into physical plant control systems (Level 1/2).",
    tags: ["SCADA", "Industrial Architecture", "Segmentation", "ISA-95"],
    reference: "ISA-95 / Purdue Enterprise Reference Architecture",
    appLinks: { mode: "assessment", scenarioId: "sc_scada_grid" }
  },

  // =========================================================================
  // LETTER R
  // =========================================================================
  {
    letter: "R",
    term: "Ransomware",
    acronym: "Ransomware",
    category: "Attacks & Exploits",
    domainTag: "attack",
    definition: "A form of malware designed to encrypt critical digital assets and system files on a targeted enterprise network, demanding a ransom payment in exchange for the cryptographic decryption keys.",
    relevance: "The highest-impact enterprise threat scenario in modern cybersecurity; modern strains combine mass encryption with double-extortion data exfiltration.",
    tags: ["Extortion", "Encryption", "Malware", "Critical Threat"],
    reference: "MITRE ATT&CK T1486",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "R",
    term: "Rate Limiting",
    acronym: "Rate Limiting",
    category: "Defenses & Controls",
    domainTag: "network",
    definition: "A defensive control implemented on network routers, web servers, or API gateways that limits the number of incoming requests a given client IP address or user token can submit within a specified time interval.",
    relevance: "Stops brute-force credential stuffing, API crawler scraping, and mitigates Layer-7 application flood attacks by dropping traffic that exceeds defined thresholds.",
    tags: ["Application Security", "WAF", "Traffic Management", "DDoS"],
    reference: "IETF RFC 6582",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "R",
    term: "RCE (Remote Code Execution)",
    acronym: "RCE",
    category: "Attacks & Exploits",
    domainTag: "appsec",
    definition: "A class of software vulnerabilities that permits an attacker to execute arbitrary shell commands, scripts, or binary payloads on a remote target system across a network connection without prior physical or authenticated access.",
    relevance: "Regarded as the most critical vulnerability type (CVSS 9.0–10.0); often serves as the initial ingress vector into cloud containers or enterprise DMZs.",
    tags: ["Critical Vulnerability", "Exploitation", "Command Injection", "Shell"],
    reference: "MITRE ATT&CK T1190, T1059",
    appLinks: { mode: "assessment", scenarioId: "sc_kernel_escape" }
  },
  {
    letter: "R",
    term: "Rogue AP (Rogue Access Point)",
    acronym: "Rogue AP",
    category: "Attacks & Exploits",
    domainTag: "wireless",
    definition: "Any wireless access point that has been installed within a network's physical perimeter without explicit administrative authorization, opening an unmonitored backdoor into the corporate LAN.",
    relevance: "Threat Vectors #45-49 in this application; adversaries deploy concealed rogue APs in conference ceilings to bypass perimeter firewalls and snoop on local traffic.",
    tags: ["Wi-Fi", "Backdoor", "Perimeter Bypass", "Wireless"],
    reference: "MITRE ATT&CK T1040",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },
  {
    letter: "R",
    term: "RPKI (Resource Public Key Infrastructure)",
    acronym: "RPKI",
    category: "Defenses & Controls",
    domainTag: "network",
    definition: "A specialized cryptographic public key infrastructure framework (RFC 6480) that enables Autonomous Systems to verify that an entity advertising a BGP IP address prefix is cryptographically authorized to originate that route (Route Origin Validation - ROV).",
    relevance: "The definitive internet-scale defense against BGP prefix hijacking; routers drop unauthorized route announcements whose origin ASN fails cryptographic validation.",
    tags: ["BGP", "Internet Security", "ROA", "Public Key"],
    reference: "IETF RFC 6480, RFC 6811",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },

  // =========================================================================
  // LETTER S
  // =========================================================================
  {
    letter: "S",
    term: "SCADA (Supervisory Control and Data Acquisition)",
    acronym: "SCADA",
    category: "ICS & SCADA",
    domainTag: "scada",
    definition: "A system architecture comprising software, networked computers, PLCs, and remote terminal units (RTUs) utilized for high-level supervisory management and telemetry monitoring of industrial operations.",
    relevance: "Core focus of Scenario 4; security controls must account for real-time latency requirements, physical safety systems, and legacy unauthenticated protocols.",
    tags: ["Operational Technology", "Industrial Control", "Critical Infrastructure", "Telemetry"],
    reference: "NIST SP 800-82",
    appLinks: { mode: "assessment", scenarioId: "sc_scada_grid" }
  },
  {
    letter: "S",
    term: "Seccomp-BPF",
    acronym: "Seccomp",
    category: "OS & Host",
    domainTag: "linux",
    definition: "Secure Computing Mode with Berkeley Packet Filter extensions; a Linux kernel security feature that allows a user program to define a declarative filter policy restricting which system calls the process may execute.",
    relevance: "Essential container hardening countermeasure that drops dangerous syscalls (e.g. `splice`, `vmsplice`, `ptrace`), neutralizing kernel exploits like Dirty Pipe even if the vulnerability exists in kernel memory.",
    tags: ["Linux", "Syscalls", "Kernel Hardening", "Containers"],
    reference: "Linux Documentation / Documentation/userspace-api/seccomp_filter.rst",
    appLinks: { mode: "assessment", scenarioId: "sc_kernel_escape" }
  },
  {
    letter: "S",
    term: "Sigma Rules",
    acronym: "Sigma",
    category: "Standards & Metrics",
    domainTag: "soc",
    definition: "An open, vendor-agnostic signature format for describing log events and behavioral detections, allowing security researchers to write detection rules once and convert them automatically into Splunk, Elastic, QRadar, or Sentinel queries.",
    relevance: "Integrated across every single threat dossier in the Detection Engineering tab, providing instant copyable detection rules for SIEM deployment.",
    tags: ["Detection Engineering", "SIEM", "Open Source", "Signatures"],
    reference: "Sigma Project / github.com/SigmaHQ/sigma",
    appLinks: { mode: "learning", attackId: "dos" }
  },
  {
    letter: "S",
    term: "SIS (Safety Instrumented System)",
    acronym: "SIS",
    category: "ICS & SCADA",
    domainTag: "scada",
    definition: "An independent safety control system specifically engineered with separate sensors, logic solvers, and final mechanical relays to safely bring an industrial plant to a safe state when process parameters exceed operational tolerances.",
    relevance: "Serves as the non-bypassable out-of-band safeguard in industrial plants; even if adversaries corrupt all software PLCs and HMI monitors, physical SIS relays cut power before equipment explodes.",
    tags: ["Physical Safety", "SCADA", "Fail-Safe", "IEC 61511"],
    reference: "IEC 61511 Standard",
    appLinks: { mode: "assessment", scenarioId: "sc_scada_grid" }
  },
  {
    letter: "S",
    term: "Slowloris",
    acronym: "Slowloris",
    category: "Attacks & Exploits",
    domainTag: "network",
    definition: "A denial-of-service attack software program that enables a single machine to take down an entire web server by opening thousands of HTTP connections and sending partial HTTP header lines at slow intervals (trickle feeding).",
    relevance: "Unlike volumetric DDoS, Slowloris requires negligible bandwidth (<100 Kbps) to starve Apache and IIS connection pools, making detection by traditional volume-based firewalls difficult.",
    tags: ["Layer 7 DoS", "HTTP", "Connection Starvation", "Application Security"],
    reference: "MITRE ATT&CK T1499.003",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "S",
    term: "SOC (Security Operations Center)",
    acronym: "SOC",
    category: "Standards & Metrics",
    domainTag: "soc",
    definition: "A centralized organizational unit and facility employing cybersecurity analysts and engineers who utilize SIEM, EDR, and SOAR tools to continuously monitor, detect, analyze, and respond to cybersecurity incidents.",
    relevance: "The operational command persona modeled throughout this application; users act as SOC Incident Commanders in Assessment Mode.",
    tags: ["SOC Operations", "Incident Response", "Monitoring", "Blue Team"],
    reference: "NIST SP 800-61",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "S",
    term: "SQL Injection (SQLi)",
    acronym: "SQLi",
    category: "Attacks & Exploits",
    domainTag: "appsec",
    definition: "A code injection vulnerability where untrusted user input is concatenated directly into SQL queries executed by backend relational database engines, allowing attackers to bypass authentication, read sensitive records, or execute OS commands.",
    relevance: "Threat Vector #11 in this application; mitigated by parameterized prepared statements, stored procedures, and strict input validation.",
    tags: ["Web Security", "OWASP Top 10", "Database", "Injection"],
    reference: "OWASP Top 10 A03:2021-Injection",
    appLinks: { mode: "learning", attackId: "sql_injection" }
  },
  {
    letter: "S",
    term: "SSRF (Server-Side Request Forgery)",
    acronym: "SSRF",
    category: "Attacks & Exploits",
    domainTag: "cloud",
    definition: "A vulnerability where an attacker coerces a vulnerable server-side web application to generate and transmit unauthorized HTTP requests to an arbitrary destination, including loopback interfaces, internal services, and cloud metadata.",
    relevance: "Chief vector for cloud account takeover; attackers exploit URL preview features to query `http://169.254.169.254` and steal temporary AWS IAM role credentials.",
    tags: ["Cloud Security", "OWASP Top 10", "IMDS", "Credential Access"],
    reference: "OWASP Top 10 A10:2021-Server-Side Request Forgery",
    appLinks: { mode: "assessment", scenarioId: "sc_cloud_breach" }
  },
  {
    letter: "S",
    term: "SSL Stripping",
    acronym: "SSL Strip",
    category: "Attacks & Exploits",
    domainTag: "wireless",
    definition: "A man-in-the-middle exploit technique introduced by Moxie Marlinspike that intercepts 302 HTTP redirects from HTTP to HTTPS, serving unencrypted HTTP versions to the user while proxying HTTPS to the destination server.",
    relevance: "Enables rogue AP operators to harvest plaintext passwords and session cookies from users who type domain names without explicitly prefixing `https://`.",
    tags: ["MITM", "TLS Downgrade", "Wireless", "Credential Harvesting"],
    reference: "MITRE ATT&CK T1557.001",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },
  {
    letter: "S",
    term: "SYN Cookies",
    acronym: "SYN Cookies",
    category: "Defenses & Controls",
    domainTag: "os",
    definition: "A TCP connection defense technique (RFC 4987) where the server kernel does not allocate memory for half-open connections in the SYN backlog table; instead, it encodes the connection state parameters directly into the Initial Sequence Number (ISN) of the SYN-ACK packet.",
    relevance: "Core operating system kernel defense against TCP SYN floods, allowing servers to survive hundreds of thousands of spoofed SYN packets without dropping legitimate handshakes.",
    tags: ["TCP", "Kernel", "SYN Flood Defense", "RFC 4987"],
    reference: "IETF RFC 4987",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "S",
    term: "SYN Flood",
    acronym: "SYN Flood",
    category: "Attacks & Exploits",
    domainTag: "network",
    definition: "A classic Layer-4 volumetric denial of service attack in which an attacker rapidly transmits a flood of TCP SYN packets with forged or unreachable source IPs, filling the server's SYN backlog queue and blocking legitimate incoming TCP handshakes.",
    relevance: "Threat Vector #1 in this application; easily executed with tools like `hping3` to render public web and API ports unresponsive.",
    tags: ["TCP", "Layer 4", "DDoS", "Connection Exhaustion"],
    reference: "MITRE ATT&CK T1498.001",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },

  // =========================================================================
  // LETTER T
  // =========================================================================
  {
    letter: "T",
    term: "Telemetry",
    acronym: "Telemetry",
    category: "Standards & Metrics",
    domainTag: "soc",
    definition: "The automated collection and transmission of diagnostic data, operational logs, packet statistics, and system events from remote network sensors, firewalls, and endpoints to a centralized monitoring system.",
    relevance: "Each threat dossier lists the essential log telemetry sources required for detection, and the assessment mode features a live animated telemetry event terminal.",
    tags: ["Monitoring", "SOC", "Logs", "Observability"],
    reference: "NIST SP 800-137",
    appLinks: { mode: "learning", attackId: "dos" }
  },
  {
    letter: "T",
    term: "Tiering Model (AD Administrative Tiering)",
    acronym: "AD Tiering",
    category: "Defenses & Controls",
    domainTag: "identity",
    definition: "An Active Directory security isolation architecture that strictly separates administrative credentials and systems into three distinct tiers: Tier 0 (Domain Controllers/PKI), Tier 1 (Enterprise Servers/Databases), and Tier 2 (Client Workstations/Devices).",
    relevance: "Strictly forbids Tier 0 Domain Admin credentials from ever logging into Tier 2 workstations, preventing ransomware operators from dumping Domain Admin hashes via LSASS.",
    tags: ["Active Directory", "Identity Isolation", "Least Privilege", "Architecture"],
    reference: "Microsoft Learn / Securing Privileged Access Reference Architecture",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "T",
    term: "TLS (Transport Layer Security)",
    acronym: "TLS",
    category: "Standards & Metrics",
    domainTag: "crypto",
    definition: "The successor cryptographic protocol to SSL (RFC 8446 - TLS 1.3) providing privacy, authentication, and data integrity over computer communications networks.",
    relevance: "Standard encryption protocol securing web, API, and 802.1X enterprise network traffic; required to prevent wiretapping and credential sniffing.",
    tags: ["Cryptography", "Transport Layer", "TLS 1.3", "Privacy"],
    reference: "IETF RFC 8446",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },

  // =========================================================================
  // LETTER U
  // =========================================================================
  {
    letter: "U",
    term: "uRPF (Unicast Reverse Path Forwarding)",
    acronym: "uRPF",
    category: "Defenses & Controls",
    domainTag: "network",
    definition: "A security feature on network routers (RFC 3704) that checks the source IP address in incoming packet headers against routing tables to verify the packet arrived on the legitimate ingress interface, dropping spoofed packets.",
    relevance: "Crucial ISP and edge countermeasure that stops DNS and NTP amplification attacks from originating within customer autonomous systems.",
    tags: ["Routing", "Anti-Spoofing", "Perimeter", "IETF RFC 3704"],
    reference: "IETF RFC 3704",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },

  // =========================================================================
  // LETTER V
  // =========================================================================
  {
    letter: "V",
    term: "VPC (Virtual Private Cloud)",
    acronym: "VPC",
    category: "Cloud & Container",
    domainTag: "cloud",
    definition: "An isolated private cloud network within a public cloud provider (AWS, GCP, Azure) resembling a traditional on-premises data center, complete with private subnets, route tables, and network security groups.",
    relevance: "Isolating microservices into private VPC subnets with strict NAT gateway proxies prevents direct inbound exploit probes and restricts outbound exfiltration.",
    tags: ["Cloud", "AWS", "Networking", "Subnets"],
    reference: "NIST SP 800-145",
    appLinks: { mode: "assessment", scenarioId: "sc_cloud_breach" }
  },
  {
    letter: "V",
    term: "VSS (Volume Shadow Copy Service)",
    acronym: "VSS",
    category: "OS & Host",
    domainTag: "os",
    definition: "A Windows operating system framework that coordinates with volume hardware and file systems to create consistent point-in-time snapshot backup copies of computer files or entire disk volumes.",
    relevance: "Heavily targeted by ransomware; threat actors invoke `vssadmin.exe delete shadows /all /quiet` before encrypting files to prevent victims from rolling back to undamaged snapshots.",
    tags: ["Windows", "Backups", "Shadow Copies", "Ransomware"],
    reference: "MITRE ATT&CK T1490",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },

  // =========================================================================
  // LETTER W
  // =========================================================================
  {
    letter: "W",
    term: "WAF (Web Application Firewall)",
    acronym: "WAF",
    category: "Defenses & Controls",
    domainTag: "appsec",
    definition: "A specialized application-layer firewall that monitors, filters, and blocks HTTP and HTTPS traffic to and from web applications, inspecting payloads for SQLi, XSS, BOLA, and SSRF attack patterns.",
    relevance: "Deploys client challenge scripts (Proof-of-Work) and terminates Slowloris connections that fail to transmit minimum data rate thresholds.",
    tags: ["Application Security", "OWASP Top 10", "Layer 7", "WAF"],
    reference: "OWASP Web Application Firewall",
    appLinks: { mode: "assessment", scenarioId: "sc_fintech_ddos" }
  },
  {
    letter: "W",
    term: "WIPS (Wireless Intrusion Prevention System)",
    acronym: "WIPS",
    category: "Defenses & Controls",
    domainTag: "wireless",
    definition: "A dedicated hardware radio and software platform that continuously scans the radio frequency spectrum for unauthorized wireless devices, rogue access points, deauth floods, and Evil Twin APs.",
    relevance: "Instantly triangulates physical location of rogue APs and transmits targeted 802.11 containment frames to neutralize rogue Wi-Fi signals in enterprise auditoriums.",
    tags: ["Wireless Security", "Rogue AP Containment", "RF Monitoring", "Defense"],
    reference: "NIST SP 800-97",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },
  {
    letter: "W",
    term: "WMI (Windows Management Instrumentation)",
    acronym: "WMI",
    category: "OS & Host",
    domainTag: "os",
    definition: "Microsoft's implementation of Web-Based Enterprise Management (WBEM) and Common Information Model (CIM) standards, providing an administrative interface for local and remote systems management.",
    relevance: "Abused in lateral movement attacks via `wmic.exe process call create` to execute remote PowerShell droppers and deploy ransomware across domain-joined servers.",
    tags: ["Windows", "Administration", "Lateral Movement", "LOLBAS"],
    reference: "MITRE ATT&CK T1047",
    appLinks: { mode: "assessment", scenarioId: "sc_health_ransomware" }
  },
  {
    letter: "W",
    term: "WPA3-Enterprise",
    acronym: "WPA3-Ent",
    category: "Defenses & Controls",
    domainTag: "wireless",
    definition: "The highest-security wireless encryption standard certified by the Wi-Fi Alliance, mandating 192-bit cryptographic protocols, Protected Management Frames (802.11w), and EAP-TLS mutual certificate authentication.",
    relevance: "Eliminates pre-shared key (PSK) cracking and neutralizes rogue Evil Twin captive portal attacks in corporate enterprise networks.",
    tags: ["Wi-Fi Alliance", "802.11", "Enterprise Security", "192-bit"],
    reference: "Wi-Fi Alliance WPA3 Specification",
    appLinks: { mode: "assessment", scenarioId: "sc_wireless_pinedrop" }
  },

  // =========================================================================
  // LETTER Z
  // =========================================================================
  {
    letter: "Z",
    term: "Zero-Day (0-Day)",
    acronym: "0-Day",
    category: "Attacks & Exploits",
    domainTag: "attack",
    definition: "A computer software vulnerability previously unknown to the vendor, product developers, and public, giving defenders 'zero days' of prior warning before active exploitation in the wild.",
    relevance: "Carries high threat severity; defenses must rely on proactive defense-in-depth, least-privilege sandboxing, and runtime anomaly monitoring rather than signature patching.",
    tags: ["Vulnerability", "Exploit", "Unknown Threat", "Patching"],
    reference: "NIST SP 800-40",
    appLinks: { mode: "assessment", scenarioId: "sc_cloud_breach" }
  },
  {
    letter: "Z",
    term: "Zero-Trust Architecture (ZTA)",
    acronym: "ZTA",
    category: "Defenses & Controls",
    domainTag: "architecture",
    definition: "An enterprise cybersecurity paradigm based on the principle of 'Never Trust, Always Verify', requiring continuous authentication, authorization, and validation of all users, devices, and network flows regardless of network location.",
    relevance: "The strategic security standard governing all countermeasures in this application; replaces obsolete perimeter-only security with continuous microsegmentation and identity verification.",
    tags: ["NIST SP 800-207", "Zero Trust", "Security Architecture", "Identity"],
    reference: "NIST SP 800-207 (Zero Trust Architecture)",
    appLinks: { mode: "assessment", scenarioId: "sc_cloud_breach" }
  },

  // =========================================================================
  // MODULE 16-19: NEW WEB APP, OWASP, DATABASE & STORAGE VECTORS (84 - 110)
  // =========================================================================
  {
    letter: "B",
    term: "Broken Access Control (BAC)",
    acronym: "A01:2021",
    category: "Attacks & Exploits",
    domainTag: "owasp",
    definition: "A critical security flaw where application authorization policies fail to restrict authenticated users to their permitted functions or data, enabling horizontal (IDOR) and vertical privilege escalation.",
    relevance: "Ranked #1 in the OWASP Top 10; root cause of multi-tenant cloud API breaches, unauthorized administrative operations, and unauthorized access to customer records.",
    tags: ["OWASP Top 10", "A01:2021", "IDOR", "Authorization", "Access Control"],
    reference: "OWASP Top 10 A01:2021 | CWE-284",
    appLinks: { mode: "learning", attackId: "broken-access-control" }
  },
  {
    letter: "C",
    term: "Cryptographic Failures",
    acronym: "A02:2021",
    category: "Attacks & Exploits",
    domainTag: "owasp",
    definition: "Vulnerabilities arising from missing or broken encryption in transit and at rest, deprecated algorithms (DES, MD5, RC4), improper key rotation, or exposure of cryptographic keys in source code.",
    relevance: "OWASP #2 risk leading directly to plaintext credential harvesting, session token forgery, and severe regulatory non-compliance penalties under GDPR and PCI-DSS.",
    tags: ["OWASP Top 10", "A02:2021", "Encryption", "Key Management", "TLS", "AES"],
    reference: "OWASP Top 10 A02:2021 | CWE-327",
    appLinks: { mode: "learning", attackId: "cryptographic-failures" }
  },
  {
    letter: "I",
    term: "Injection (OWASP Injection Flaws)",
    acronym: "A03:2021",
    category: "Attacks & Exploits",
    domainTag: "owasp",
    definition: "A wide class of flaws where untrusted user input is concatenated directly into interpreters (SQL, NoSQL, OS Command, LDAP) without contextual escaping or query parameterization.",
    relevance: "Enables arbitrary syntax execution, remote command execution, database schema dumps, and host operating system takeover.",
    tags: ["OWASP Top 10", "A03:2021", "SQLi", "Command Injection", "Sanitization"],
    reference: "OWASP Top 10 A03:2021 | CWE-79, CWE-89",
    appLinks: { mode: "learning", attackId: "owasp-injection" }
  },
  {
    letter: "I",
    term: "Insecure Design",
    acronym: "A04:2021",
    category: "Attacks & Exploits",
    domainTag: "owasp",
    definition: "A security category focusing on architectural and design flaws that cannot be fixed by a perfect code implementation, representing missing threat modeling and missing secure design patterns.",
    relevance: "Distinguishes design defects (e.g. lack of anti-automation, flawed password reset logic) from coding bugs; requires architectural risk analysis prior to implementation.",
    tags: ["OWASP Top 10", "A04:2021", "Threat Modeling", "Architecture", "Design Flaws"],
    reference: "OWASP Top 10 A04:2021 | CWE-209, CWE-256",
    appLinks: { mode: "learning", attackId: "insecure-design" }
  },
  {
    letter: "S",
    term: "Security Misconfiguration",
    acronym: "A05:2021",
    category: "Attacks & Exploits",
    domainTag: "owasp",
    definition: "The failure to implement secure default configuration controls across applications, web servers, databases, or cloud accounts, including default passwords, debug headers, and exposed admin panels.",
    relevance: "Extremely common enterprise attack vector; automated recon scanners constantly scan for default cloud permissions, open S3 buckets, and verbose stack traces.",
    tags: ["OWASP Top 10", "A05:2021", "Hardening", "CIS Benchmark", "Cloud Config"],
    reference: "OWASP Top 10 A05:2021 | CWE-16",
    appLinks: { mode: "learning", attackId: "security-misconfiguration" }
  },
  {
    letter: "V",
    term: "Vulnerable and Outdated Components",
    acronym: "A06:2021",
    category: "Attacks & Exploits",
    domainTag: "owasp",
    definition: "Risks caused by deploying third-party libraries, container base images, operating system modules, or frameworks that contain publicly known unpatched vulnerabilities (CVEs).",
    relevance: "Exploited in major catastrophic breaches (Log4Shell, Equifax Apache Struts); mitigated via Software Bill of Materials (SBOM) and Software Composition Analysis (SCA).",
    tags: ["OWASP Top 10", "A06:2021", "SBOM", "CVE", "Supply Chain", "SCA"],
    reference: "OWASP Top 10 A06:2021 | CWE-1104",
    appLinks: { mode: "learning", attackId: "vulnerable-components" }
  },
  {
    letter: "I",
    term: "Identification and Authentication Failures",
    acronym: "A07:2021",
    category: "Attacks & Exploits",
    domainTag: "owasp",
    definition: "Flaws in authentication mechanisms that allow adversaries to compromise passwords, tokens, or sessions, including credential stuffing, missing brute-force lockouts, and weak session IDs.",
    relevance: "Enables automated botnet credential reuse from public breach corpuses and session hijacking; requires mandatory FIDO2/MFA and secure session handling.",
    tags: ["OWASP Top 10", "A07:2021", "Authentication", "MFA", "Session Hijacking"],
    reference: "OWASP Top 10 A07:2021 | CWE-287, CWE-384",
    appLinks: { mode: "learning", attackId: "auth-failures" }
  },
  {
    letter: "S",
    term: "Software and Data Integrity Failures",
    acronym: "A08:2021",
    category: "Attacks & Exploits",
    domainTag: "owasp",
    definition: "Vulnerabilities where software code, packages, or updates are integrated from untrusted sources without cryptographic signature verification or validation, including insecure deserialization.",
    relevance: "Primary mechanism of software supply chain compromises (e.g. SolarWinds, poisoned npm/PyPI dependencies); countered with Sigstore and cryptographic provenance.",
    tags: ["OWASP Top 10", "A08:2021", "CI/CD", "Integrity", "Deserialization", "Code Signing"],
    reference: "OWASP Top 10 A08:2021 | CWE-502, CWE-829",
    appLinks: { mode: "learning", attackId: "integrity-failures" }
  },
  {
    letter: "S",
    term: "Security Logging and Monitoring Failures",
    acronym: "A09:2021",
    category: "Attacks & Exploits",
    domainTag: "owasp",
    definition: "The absence or insufficiency of security audit event logging, centralized SIEM correlation, and real-time alerting on anomalous activities such as brute force attempts or privilege abuse.",
    relevance: "Drastically extends attacker dwell time (often 200+ days); without comprehensive audit logs, incident detection, active containment, and forensic root cause analysis fail.",
    tags: ["OWASP Top 10", "A09:2021", "SIEM", "SOC", "Audit Trails", "Dwell Time"],
    reference: "OWASP Top 10 A09:2021 | CWE-778",
    appLinks: { mode: "learning", attackId: "logging-failures" }
  },
  {
    letter: "S",
    term: "Server-Side Request Forgery (SSRF)",
    acronym: "SSRF",
    category: "Attacks & Exploits",
    domainTag: "owasp",
    definition: "A vulnerability where a web application is manipulated into sending HTTP/TCP requests to arbitrary internal or external addresses, commonly targeting cloud instance metadata services (IMDS).",
    relevance: "OWASP #10 vulnerability responsible for major cloud data breaches; enables theft of temporary cloud IAM credentials from 169.254.169.254 and internal microservice port scanning.",
    tags: ["OWASP Top 10", "A10:2021", "SSRF", "Cloud Metadata", "IMDSv2", "Pivot"],
    reference: "OWASP Top 10 A10:2021 | CWE-918",
    appLinks: { mode: "learning", attackId: "ssrf-attack" }
  },
  {
    letter: "D",
    term: "Directory Traversal (Web Path Traversal)",
    acronym: "Dot-Dot-Slash",
    category: "Attacks & Exploits",
    domainTag: "app",
    definition: "An exploit leveraging inadequate path sanitization in HTTP file access parameters, using sequence strings like `../` to access files stored outside the web root folder.",
    relevance: "Enables reading arbitrary system files like `/etc/passwd`, application configuration settings, database connection strings, and source code files.",
    tags: ["Path Traversal", "CWE-22", "LFI", "Web Application", "Directory Traversal"],
    reference: "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
    appLinks: { mode: "learning", attackId: "web-directory-traversal" }
  },
  {
    letter: "I",
    term: "Input Filtering Attack (Filter Bypass)",
    acronym: "WAF Bypass",
    category: "Attacks & Exploits",
    domainTag: "app",
    definition: "Techniques used by adversaries to circumvent Web Application Firewall (WAF) rule sets and input validation routines using payload obfuscation, double URL encoding, and alternative character encodings.",
    relevance: "Demonstrates that blacklist-based filtering is inherently brittle; robust applications require strict allow-list schema validation and parameterized execution.",
    tags: ["WAF Evasion", "Input Validation", "Filter Bypass", "Encoding", "Sanitization"],
    reference: "OWASP WAF Evasion Guidelines | CWE-20",
    appLinks: { mode: "learning", attackId: "input-filtering-attack" }
  },
  {
    letter: "C",
    term: "Code Injection (Web Application RCE)",
    acronym: "RCE",
    category: "Attacks & Exploits",
    domainTag: "app",
    definition: "The exploitation of applications that pass untrusted input into server-side interpreter functions (like `eval()` or OS shell runners) without sanitization, resulting in arbitrary code execution.",
    relevance: "Grants full Remote Code Execution (RCE) with the privileges of the web application server process (e.g. `www-data`), providing an immediate pivot into host internals.",
    tags: ["RCE", "Code Injection", "eval()", "SSTI", "Server-Side Execution"],
    reference: "CWE-94: Improper Control of Generation of Code",
    appLinks: { mode: "learning", attackId: "web-code-injection" }
  },
  {
    letter: "S",
    term: "SQL Injection (Web SQLi)",
    acronym: "SQLi",
    category: "Attacks & Exploits",
    domainTag: "app",
    definition: "The insertion of malicious SQL control fragments into HTTP request parameters that are concatenated into dynamic database queries, overriding intended database query logic.",
    relevance: "Enables authentication bypass (`' OR 1=1 --`), mass extraction of customer tables, data deletion, and OS shell spawning via stored procedures like `xp_cmdshell`.",
    tags: ["SQLi", "CWE-89", "Parameterized Queries", "Database", "Authentication Bypass"],
    reference: "OWASP SQL Injection Prevention Cheat Sheet | CWE-89",
    appLinks: { mode: "learning", attackId: "web-sql-injection" }
  },
  {
    letter: "C",
    term: "Cross-Site Scripting (XSS)",
    acronym: "XSS",
    category: "Attacks & Exploits",
    domainTag: "app",
    definition: "A client-side code injection flaw where an adversary injects malicious JavaScript into trusted web applications, executing within the browser context of unsuspecting users.",
    relevance: "Includes Reflected, Stored, and DOM-based variants; allows attackers to hijack session cookies (lacking HttpOnly), capture keystrokes, and perform unauthorized user actions.",
    tags: ["XSS", "CWE-79", "CSP", "Client-Side", "DOM", "Cookie Theft"],
    reference: "OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet",
    appLinks: { mode: "learning", attackId: "web-xss" }
  },
  {
    letter: "C",
    term: "Cross-Site Request Forgery (CSRF)",
    acronym: "CSRF",
    category: "Attacks & Exploits",
    domainTag: "app",
    definition: "An attack that tricks a victim's authenticated browser into executing unauthorized state-changing HTTP requests against a vulnerable web application.",
    relevance: "Enables unauthorized fund transfers, email changes, and password updates without user awareness; mitigated using Anti-CSRF Synchronizer Tokens and SameSite cookies.",
    tags: ["CSRF", "CWE-352", "SameSite", "Anti-CSRF Token", "Session Riding"],
    reference: "OWASP CSRF Prevention Cheat Sheet | CWE-352",
    appLinks: { mode: "learning", attackId: "csrf" }
  },
  {
    letter: "H",
    term: "HTTP Request Smuggling (HRS)",
    acronym: "HRS",
    category: "Attacks & Exploits",
    domainTag: "app",
    definition: "An advanced desynchronization attack exploiting ambiguities in how front-end reverse proxies and back-end web servers interpret HTTP request boundaries (CL.TE, TE.CL, TE.TE).",
    relevance: "Enables cache poisoning, bypass of front-end security filters, session hijacking of subsequent requests on shared keep-alive connections, and credential theft.",
    tags: ["Desync", "HTTP Request Smuggling", "Content-Length", "Transfer-Encoding", "Reverse Proxy"],
    reference: "CWE-444: Inconsistent Interpretation of HTTP Requests | RFC 7230",
    appLinks: { mode: "learning", attackId: "http-request-smuggling" }
  },
  {
    letter: "D",
    term: "Database Privilege Escalation",
    acronym: "DB-PrivEsc",
    category: "Attacks & Exploits",
    domainTag: "database",
    definition: "An exploit wherein a low-privileged database user account exploits database engine vulnerabilities, flawed SECURITY DEFINER procedures, or weak role grants to achieve DBA/sysadmin privileges.",
    relevance: "Transforms restricted database application accounts into full database superusers, granting access to master tables, disabling auditing, and executing OS commands.",
    tags: ["Database", "Privilege Escalation", "DBA", "PostgreSQL", "SQL Server", "Oracle"],
    reference: "MITRE ATT&CK T1068, T1078 | CIS Database Benchmark",
    appLinks: { mode: "learning", attackId: "db-privilege-escalation" }
  },
  {
    letter: "U",
    term: "Unauthorized Database Access",
    acronym: "UDA",
    category: "Attacks & Exploits",
    domainTag: "database",
    definition: "Direct access gained to a database server without authentication or via exposed network listening ports on public interfaces (e.g. exposed MongoDB, Redis, or Elasticsearch clusters).",
    relevance: "Responsible for widespread automated data exposures where search engines (Shodan, Censys) discover unauthenticated database clusters containing millions of sensitive records.",
    tags: ["Database Security", "Access Control", "Network Exposure", "Misconfiguration", "Unauthenticated"],
    reference: "CWE-306: Missing Authentication for Critical Function",
    appLinks: { mode: "learning", attackId: "unauthorized-db-access" }
  },
  {
    letter: "B",
    term: "Blind SQL Injection (Inferential SQLi)",
    acronym: "Blind-SQLi",
    category: "Attacks & Exploits",
    domainTag: "database",
    definition: "A SQL injection technique where the vulnerable application suppresses SQL error messages and query output, forcing the attacker to reconstruct database contents through true/false Boolean conditions or injected time delays.",
    relevance: "Common in enterprise applications; tools like sqlmap leverage binary search heuristics to extract entire database schemas and password hashes bit-by-bit.",
    tags: ["Blind SQLi", "Boolean Blind", "Time-Based", "Inference", "Database"],
    reference: "OWASP Blind SQL Injection Cheat Sheet | CWE-89",
    appLinks: { mode: "learning", attackId: "blind-sql-injection" }
  },
  {
    letter: "D",
    term: "Database Enumeration",
    acronym: "DB-Enum",
    category: "Attacks & Exploits",
    domainTag: "database",
    definition: "The systematic querying and harvesting of database metadata tables (`information_schema`, `sys.tables`, `pg_catalog`) to discover table names, column types, and stored procedure names.",
    relevance: "Critical reconnaissance milestone allowing attackers to pinpoint high-value target tables (e.g. `users`, `cardholder_data`, `api_keys`) and craft targeted extraction queries.",
    tags: ["Enumeration", "Reconnaissance", "Information Schema", "Metadata", "Database"],
    reference: "MITRE ATT&CK T1087, T1082 | CWE-200",
    appLinks: { mode: "learning", attackId: "db-enumeration" }
  },
  {
    letter: "D",
    term: "Data Leakage (Cloud Storage Exposure)",
    acronym: "Data-Leak",
    category: "Attacks & Exploits",
    domainTag: "storage",
    definition: "The unauthorized or accidental exposure of protected enterprise files, database dumps, or logs to public internet users, usually via open cloud object storage permissions.",
    relevance: "Frequently observed in improperly configured AWS S3 buckets, Azure Blob containers, or Google Cloud Storage buckets; results in severe regulatory enforcement and reputational damage.",
    tags: ["Storage", "S3 Bucket", "Data Leakage", "Confidentiality", "Cloud Security"],
    reference: "NIST SP 800-53 SC-8, SC-28 | CWE-200",
    appLinks: { mode: "learning", attackId: "data-leakage" }
  },
  {
    letter: "D",
    term: "Data Tampering (Integrity Subversion)",
    acronym: "Tampering",
    category: "Attacks & Exploits",
    domainTag: "storage",
    definition: "The intentional unauthorized alteration, falsification, or corruption of records stored within files, databases, or cloud object stores to undermine system reliability or conceal illicit activity.",
    relevance: "Threatens data integrity in financial balances, healthcare patient charts, or security audit logs; defended via cryptographic HMACs, WORM storage, and tamper-evident append-only ledgers.",
    tags: ["Integrity", "Tampering", "WORM Storage", "HMAC", "Data Modification"],
    reference: "STRIDE Threat Model (Tampering) | ISO/IEC 27001 A.12",
    appLinks: { mode: "learning", attackId: "data-tampering" }
  },
  {
    letter: "U",
    term: "Unauthorized Data Access (Storage Tier)",
    acronym: "UDA-Storage",
    category: "Attacks & Exploits",
    domainTag: "storage",
    definition: "Bypassing storage bucket ACLs, IAM policy conditions, or encryption keys to query, download, or index proprietary corporate document repositories.",
    relevance: "Accomplished using compromised long-lived cloud credentials, insecure presigned URLs, or unsegmented internal storage networks lacking Privileged Access Management (PAM).",
    tags: ["Storage ACL", "IAM Policy", "Access Control", "Data Breach", "Object Storage"],
    reference: "MITRE ATT&CK T1530: Data from Cloud Storage | CWE-284",
    appLinks: { mode: "learning", attackId: "unauthorized-data-access" }
  },
  {
    letter: "D",
    term: "Data Exfiltration",
    acronym: "Exfiltration",
    category: "Attacks & Exploits",
    domainTag: "storage",
    definition: "The unauthorized covert copying, transfer, or upload of confidential corporate information from an enterprise network to an external system controlled by a threat actor.",
    relevance: "The climax of data theft and corporate espionage campaigns; executed using encrypted cloud sync utilities (rclone), DNS tunnels, ICMP covert channels, or web hooks.",
    tags: ["Exfiltration", "MITRE T1048", "DLP", "Data Theft", "DNS Tunneling"],
    reference: "MITRE ATT&CK TA0010: Exfiltration",
    appLinks: { mode: "learning", attackId: "data-exfiltration" }
  },
  {
    letter: "D",
    term: "Data Destruction (Wiper & Storage Erasure)",
    acronym: "Wiper",
    category: "Attacks & Exploits",
    domainTag: "storage",
    definition: "The deliberate, irreversible deletion or cryptographic scrambling of storage volumes, cloud snapshots, databases, and backup systems to paralyze operations.",
    relevance: "Employed in destructive nation-state conflicts (HermeticWiper, CaddyWiper) and ransomware extortion to eliminate backup restoration capabilities; requires immutable WORM backups.",
    tags: ["Data Destruction", "Wiper", "Immutable Backups", "Ransomware", "Disaster Recovery"],
    reference: "MITRE ATT&CK T1485: Data Destruction | NIST SP 800-34",
    appLinks: { mode: "learning", attackId: "data-destruction" }
  },
  {
    letter: "I",
    term: "Input Filtering & Schema Validation",
    acronym: "IFV",
    category: "Defenses & Controls",
    domainTag: "app",
    definition: "The systematic enforcement of strict data type, boundary, character set, and format specifications on all incoming data fields before application processing using strict positive allow-lists.",
    relevance: "Foundational control preventing SQLi, XSS, Command Injection, and Path Traversal; must be paired with context-aware output encoding to ensure end-to-end security.",
    tags: ["Input Validation", "Defenses", "Sanitization", "Allow-Listing", "OWASP"],
    reference: "OWASP Input Validation Cheat Sheet | NIST SP 800-53 SI-10",
    appLinks: { mode: "learning", attackId: "input-filtering-attack" }
  }
];

// =============================================================================
// GLOSSARY STATE MANAGEMENT & RENDERING
// =============================================================================

let currentGlossaryCategory = "all";
let glossarySearchQuery = "";
let currentActiveLetter = "all";

document.addEventListener("DOMContentLoaded", () => {
  initGlossary();
});

function initGlossary() {
  const badgeEl = document.getElementById("glossary-term-badge");
  if (badgeEl) badgeEl.textContent = `${GLOSSARY_DATA.length} Terms`;
  const countEl = document.getElementById("glossary-term-count");
  if (countEl) countEl.textContent = `${GLOSSARY_DATA.length} Terms`;
  renderAlphabetBar();
  renderGlossaryCategoryFilter();
  initGlossarySearch();
  renderGlossaryList();
}

function getDistinctLetters() {
  const letters = new Set();
  GLOSSARY_DATA.forEach(item => {
    letters.add(item.letter.toUpperCase());
  });
  return Array.from(letters).sort();
}

function renderAlphabetBar() {
  const container = document.getElementById("glossary-alphabet-bar");
  if (!container) return;

  const letters = getDistinctLetters();
  let html = `<button class="alpha-btn ${currentActiveLetter === 'all' ? 'active' : ''}" data-letter="all">ALL</button>`;

  letters.forEach(letter => {
    html += `<button class="alpha-btn ${currentActiveLetter === letter ? 'active' : ''}" data-letter="${letter}">${letter}</button>`;
  });

  container.innerHTML = html;

  container.querySelectorAll(".alpha-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      container.querySelectorAll(".alpha-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentActiveLetter = btn.getAttribute("data-letter");
      renderGlossaryList();

      if (currentActiveLetter !== "all") {
        const anchor = document.getElementById(`letter-group-${currentActiveLetter}`);
        if (anchor) {
          anchor.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }
    });
  });
}

function renderGlossaryCategoryFilter() {
  const container = document.getElementById("glossary-category-pills");
  if (!container) return;

  const categories = [
    "all",
    "Attacks & Exploits",
    "Defenses & Controls",
    "Network & Routing",
    "OS & Host",
    "Identity & AD",
    "Cloud & Container",
    "ICS & SCADA",
    "Standards & Metrics"
  ];

  container.innerHTML = categories.map(cat => {
    const isAct = currentGlossaryCategory === cat;
    const label = cat === "all" ? "All Terms" : cat;
    return `<button class="filter-pill ${isAct ? 'active' : ''}" data-category="${cat}">${label}</button>`;
  }).join("");

  container.querySelectorAll(".filter-pill").forEach(btn => {
    btn.addEventListener("click", () => {
      container.querySelectorAll(".filter-pill").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentGlossaryCategory = btn.getAttribute("data-category");
      renderGlossaryList();
    });
  });
}

function initGlossarySearch() {
  const searchInput = document.getElementById("glossary-search-input");
  const clearBtn = document.getElementById("glossary-clear-search-btn");

  if (!searchInput) return;

  searchInput.addEventListener("input", (e) => {
    glossarySearchQuery = e.target.value.trim().toLowerCase();
    if (clearBtn) clearBtn.style.display = glossarySearchQuery.length > 0 ? "block" : "none";
    renderGlossaryList();
  });

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      searchInput.value = "";
      glossarySearchQuery = "";
      clearBtn.style.display = "none";
      renderGlossaryList();
      searchInput.focus();
    });
  }
}

function renderGlossaryList() {
  const container = document.getElementById("glossary-cards-container");
  const countEl = document.getElementById("glossary-term-count");
  if (!container) return;

  // Filter items
  const filtered = GLOSSARY_DATA.filter(item => {
    const matchesCategory = currentGlossaryCategory === "all" || item.category === currentGlossaryCategory;
    const matchesLetter = currentActiveLetter === "all" || item.letter.toUpperCase() === currentActiveLetter.toUpperCase();
    const matchesSearch = glossarySearchQuery === "" ||
      item.term.toLowerCase().includes(glossarySearchQuery) ||
      item.acronym.toLowerCase().includes(glossarySearchQuery) ||
      item.definition.toLowerCase().includes(glossarySearchQuery) ||
      item.relevance.toLowerCase().includes(glossarySearchQuery) ||
      item.tags.some(t => t.toLowerCase().includes(glossarySearchQuery)) ||
      (item.reference && item.reference.toLowerCase().includes(glossarySearchQuery));
    
    return matchesCategory && matchesLetter && matchesSearch;
  });

  if (countEl) {
    countEl.textContent = `${filtered.length} Terms`;
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="glossary-empty-state">
        <svg viewBox="0 0 24 24" width="32" height="32" stroke="currentColor" fill="none" stroke-width="2">
          <circle cx="11" cy="11" r="8"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        </svg>
        <p>No glossary terms matched your search or filter criteria.</p>
        <button class="glossary-reset-filter-btn" id="btn-reset-glossary-filters">Clear Search & Filters</button>
      </div>
    `;

    const resetBtn = document.getElementById("btn-reset-glossary-filters");
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        currentGlossaryCategory = "all";
        glossarySearchQuery = "";
        currentActiveLetter = "all";
        const searchInput = document.getElementById("glossary-search-input");
        if (searchInput) searchInput.value = "";
        renderAlphabetBar();
        renderGlossaryCategoryFilter();
        renderGlossaryList();
      });
    }
    return;
  }

  // Group by Letter
  const grouped = {};
  filtered.forEach(item => {
    const letKey = item.letter.toUpperCase();
    if (!grouped[letKey]) grouped[letKey] = [];
    grouped[letKey].push(item);
  });

  const sortedLetters = Object.keys(grouped).sort();

  let html = "";

  sortedLetters.forEach(letter => {
    html += `
      <div class="glossary-letter-section" id="letter-group-${letter}">
        <div class="letter-section-header">
          <div class="letter-badge-circle">${letter}</div>
          <span class="letter-section-count">${grouped[letter].length} Term${grouped[letter].length > 1 ? 's' : ''}</span>
          <div class="letter-section-line"></div>
        </div>
        <div class="glossary-grid">
    `;

    grouped[letter].forEach(termItem => {
      // Build tag chips
      const tagChips = termItem.tags.map(t => `<span class="glossary-chip">${t}</span>`).join("");

      // Build link button if applicable
      let appLinkHtml = "";
      if (termItem.appLinks) {
        if (termItem.appLinks.mode === "learning") {
          appLinkHtml = `
            <button class="glossary-app-link-btn learning" onclick="jumpToLearningAttack('${termItem.appLinks.attackId}')" title="Explore in Learning Mode">
              <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" fill="none" stroke-width="2">
                <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>
                <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>
              </svg>
              <span>Explore in Learning Mode</span>
            </button>
          `;
        } else if (termItem.appLinks.mode === "assessment") {
          appLinkHtml = `
            <button class="glossary-app-link-btn assessment" onclick="jumpToAssessmentScenario('${termItem.appLinks.scenarioId}')" title="Test in Assessment Mode">
              <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" fill="none" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>Test in Assessment Mode</span>
            </button>
          `;
        }
      }

      html += `
        <div class="glossary-term-card">
          <div class="term-card-header">
            <div>
              <div class="term-category-tag ${termItem.domainTag}">${termItem.category.toUpperCase()}</div>
              <h3 class="term-title">${termItem.term}</h3>
            </div>
            <span class="term-acronym-badge">${termItem.acronym}</span>
          </div>

          <p class="term-definition">${termItem.definition}</p>

          <div class="term-relevance-box">
            <span class="relevance-title">Operational Context & Application Role:</span>
            <p class="relevance-text">${termItem.relevance}</p>
          </div>

          <div class="term-footer-meta">
            <div class="term-chips-row">
              ${tagChips}
            </div>
            ${termItem.reference ? `<span class="term-ref-tag"><svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" fill="none" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg> ${termItem.reference}</span>` : ''}
          </div>

          ${appLinkHtml ? `<div class="term-action-row">${appLinkHtml}</div>` : ''}
        </div>
      `;
    });

    html += `
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

// =============================================================================
// GLOBAL NAVIGATION HOOKS
// =============================================================================

function jumpToLearningAttack(attackId) {
  if (typeof switchAppMode === "function") {
    switchAppMode("learning");
  }
  if (typeof loadAttack === "function") {
    loadAttack(attackId);
    window.location.hash = `${attackId}?tab=anatomy&filter=all`;
  }
}

function jumpToAssessmentScenario(scenarioId) {
  if (typeof switchAppMode === "function") {
    switchAppMode("assessment");
  }
  if (typeof loadScenario === "function") {
    loadScenario(scenarioId);
    window.location.hash = `assessment?scenario=${scenarioId}`;
  }
}

// Global exports
window.jumpToLearningAttack = jumpToLearningAttack;
window.jumpToAssessmentScenario = jumpToAssessmentScenario;
