/**
 * CYBER ATTACK BOOK - ASSESSMENT MODE & DEFENSE SIMULATION ENGINE
 * Realistic Cyber Incident Scenarios, Cost-to-Defend Budgeting & Attack Mitigation Engine
 */

// =============================================================================
// SCENARIOS REPOSITORY (6 Realistic High-Stakes Enterprise Scenarios)
// =============================================================================

const SCENARIOS_DATA = [
  // ---------------------------------------------------------------------------
  // SCENARIO 1: FINANCIAL & BANKING CORE
  // ---------------------------------------------------------------------------
  {
    id: "sc_fintech_ddos",
    title: "Project Blackout: Banking Core Multi-Vector DDoS & BGP Extortion",
    shortTitle: "Project Blackout (Banking DDoS)",
    domain: "Financial Services & Perimeter Routing",
    domainTag: "fintech",
    difficulty: "High",
    budget: 120000,
    potentialDamage: 4500000,
    threatActor: "Lazarus-aligned / DarkStorm Syndicate",
    targetAsset: "SWIFT Settlement Gateway & Edge BGP Routers",
    timeWindow: "30 Minutes until Settlement Cutoff",
    summary: "During quarter-end interbank settlement, an extortion cartel initiates a massive multi-layered volumetric and protocol assault against Meridian Global Bank. They flood border routers, inject false BGP prefixes to hijack transaction tokens, and choke API gateways with Slowloris connections.",
    briefing: "At 14:02 UTC, Meridian Bank's primary edge transit providers flagged a massive 450 Gbps ingress spike. Concurrently, rogue BGP route announcements appeared on regional internet exchanges attempting to divert Meridian's /24 prefixes to an unauthorized AS in Eastern Europe. The attackers demand 50 BTC within 45 minutes or threat to completely sever real-time payment settlement channels.",
    attacks: [
      {
        id: "atk_syn_slowloris",
        name: "SYN Flood & Slowloris Application Exhaustion",
        shortName: "SYN & Slowloris Flood",
        mitre: "T1498.001, T1499.003",
        severity: "critical",
        damage: 1200000,
        stage: "Layer 4 & Layer 7 Flooding",
        desc: "80 Million pps TCP SYN packets exhaust state tables on perimeter firewalls, while 45,000 trickle HTTP Slowloris connections exhaust web server worker threads.",
        indicators: "Firewall connection table 99% full; thousands of SYN_RECV states; Apache/Nginx worker pool starvation."
      },
      {
        id: "atk_bgp_hijack",
        name: "BGP Prefix Hijacking & Autonomous System Masquerading",
        shortName: "BGP Prefix Hijack",
        mitre: "T1584, T1557",
        severity: "critical",
        damage: 2100000,
        stage: "Internet Routing Poisoning",
        desc: "Adversary broadcasts fraudulent BGP route announcements for Meridian's public CIDR block (/24), siphoning API transactions and user auth credentials to an offshore man-in-the-middle node.",
        indicators: "Global BGP routing anomaly alerts; asymmetric latency spikes; foreign autonomous system claiming ownership of Meridian IP ranges."
      },
      {
        id: "atk_dns_amp",
        name: "DNS Amplification Reflected UDP Ingress",
        shortName: "DNS UDP Amplification",
        mitre: "T1498.002",
        severity: "high",
        damage: 1200000,
        stage: "Bandwidth Saturation",
        desc: "Spoofed EDNS0 queries sent to open public recursive resolvers reflect a 60x amplified UDP flood against Meridian's upstream ISP transit links, causing total link saturation.",
        indicators: "High volume of UDP port 53 packets; 100% upstream link saturation; packet drops across external border interfaces."
      }
    ],
    defenses: [
      {
        id: "def_bgp_scrub",
        name: "Cloud BGP Anycast Scrubbing Center & GRE Diverter",
        shortName: "Cloud Anycast Scrubbing",
        tier: "Perimeter & Cloud Transit",
        cost: 35000,
        desc: "Announces prefixes via global Anycast scrubbing centers (e.g. Cloudflare Magic Transit / Akamai Prolexic), filtering volumetric Layer 3/4 floods before forwarding clean packets via GRE tunnels.",
        mitigations: [
          { attackId: "atk_syn_slowloris", percent: 45 },
          { attackId: "atk_dns_amp", percent: 90 },
          { attackId: "atk_bgp_hijack", percent: 35 }
        ]
      },
      {
        id: "def_rpki_urpf",
        name: "RPKI Route Origin Validation & Strict Ingress uRPF",
        shortName: "RPKI & Ingress uRPF",
        tier: "Edge Routing & Protocol Hardening",
        cost: 25000,
        desc: "Mandates Route Origin Authorizations (ROAs) with cryptographic RPKI validation on all upstream Tier-1 BGP peers and enforces unicast Reverse Path Forwarding (uRPF) to drop spoofed IP sources.",
        mitigations: [
          { attackId: "atk_bgp_hijack", percent: 75 },
          { attackId: "atk_dns_amp", percent: 30 }
        ]
      },
      {
        id: "def_syn_cookies_acls",
        name: "Hardware SYN Cookie Offload & Border Rate Limiting",
        shortName: "Hardware SYN Cookies & ACLs",
        tier: "Network Firewalls & OS Kernel",
        cost: 20000,
        desc: "Offloads TCP SYN cookie validation directly onto border hardware ASICs and programs stateless ACLs to throttle unauthorized handshake rates before they reach internal connection tables.",
        mitigations: [
          { attackId: "atk_syn_slowloris", percent: 55 }
        ]
      },
      {
        id: "def_waf_rate_limit",
        name: "Adaptive Cloud WAF & Dynamic Proof-of-Work Challenge",
        shortName: "Adaptive WAF & PoW",
        tier: "Application Security",
        cost: 25000,
        desc: "Enforces strict minimum data transmission rates (dropping Slowloris connections taking >10s to send headers) and deploys cryptographic client-side Proof-of-Work challenges to choke bot traffic.",
        mitigations: [
          { attackId: "atk_syn_slowloris", percent: 50 }
        ]
      },
      {
        id: "def_anycast_dns_shield",
        name: "Distributed Anycast DNS Shield & Response Rate Limiting (RRL)",
        shortName: "Anycast DNS & RRL Shield",
        tier: "DNS Infrastructure",
        cost: 15000,
        desc: "Deploys geographically dispersed redundant authoritative DNS nodes and activates Response Rate Limiting (RRL) to stop recursive amplification abuse.",
        mitigations: [
          { attackId: "atk_dns_amp", percent: 50 }
        ]
      }
    ]
  },

  // ---------------------------------------------------------------------------
  // SCENARIO 2: HEALTHCARE & ACTIVE DIRECTORY RANSOMWARE
  // ---------------------------------------------------------------------------
  {
    id: "sc_health_ransomware",
    title: "Operation BlackCat: Hospital Enterprise Ransomware & AD Takeover",
    shortTitle: "Operation BlackCat (Hospital Ransomware)",
    domain: "Healthcare Enterprise & Active Directory",
    domainTag: "healthcare",
    difficulty: "Critical",
    budget: 150000,
    potentialDamage: 6500000,
    threatActor: "BlackCat / ALPHV Ransomware Affiliate",
    targetAsset: "Patient Medical Records (EHR) & Domain Controllers",
    timeWindow: "20 Minutes before Mass File Encryption",
    summary: "A human-operated ransomware syndicate breached an oncology clinic laptop via a weaponized email macro. They dumped LSASS memory for Domain Admin credentials, queried Active Directory via BloodHound, and are currently staging ChaCha20 encryption payloads across 400 medical servers.",
    briefing: "Urgent red alert from the hospital SOC: Workstation PC-ONC-04 was observed running suspicious PowerShell commands at 03:15 AM. Shortly after, Event ID 4769 (Kerberos Ticket Request) spiked as attackers executed Kerberoasting against SQL service accounts. Active Directory replication traffic has surged, and shadow copies are being methodically deleted via vssadmin.",
    attacks: [
      {
        id: "atk_kerberoast",
        name: "Kerberoasting & LSASS Memory Credential Dumping",
        shortName: "Kerberoasting & LSASS Dump",
        mitre: "T1558.003, T1003.001",
        severity: "critical",
        damage: 2000000,
        stage: "Credential Access & Privilege Escalation",
        desc: "Adversaries extract Kerberos TGS service tickets for high-privileged SPN accounts and dump LSASS memory on compromised nurse stations to retrieve unencrypted plaintext Domain Admin passwords.",
        indicators: "Abnormal surge in Event ID 4769 with RC4 encryption (0x17); Sysmon Event 10 LSASS handle opens by untrusted executables."
      },
      {
        id: "atk_lateral_smb",
        name: "Lateral Movement via Pass-the-Hash & WMI Remote Exec",
        shortName: "Pass-the-Hash & WMI Spread",
        mitre: "T1550.002, T1047",
        severity: "critical",
        damage: 1800000,
        stage: "Enterprise Lateral Propagation",
        desc: "With compromised Domain Admin hashes, adversaries remotely invoke `wmic process call create` and deploy ransomware binary droppers across hospital subnets over SMB Port 445.",
        indicators: "High volume of Event ID 4624 Type 3 network logons with admin credentials; anomalous outbound connections over TCP 445."
      },
      {
        id: "atk_ransomware_vss",
        name: "Shadow Copy Purge & Mass Multi-Threaded File Encryption",
        shortName: "VSS Deletion & Ransomware",
        mitre: "T1490, T1486",
        severity: "critical",
        damage: 2700000,
        stage: "Total Impact & Disruption",
        desc: "The attacker invokes `vssadmin.exe delete shadows /all /quiet` to destroy local recovery snapshots, followed by multi-threaded ChaCha20+RSA-4096 encryption of patient clinical databases.",
        indicators: "Process creation for vssadmin with shadow deletion arguments; millions of disk I/O write operations per second; .blackcat file extensions appearing."
      }
    ],
    defenses: [
      {
        id: "def_edr_isolation",
        name: "Automated EDR Host Isolation & LSASS Credential Guard",
        shortName: "EDR Isolation & Credential Guard",
        tier: "Endpoint & Host Security",
        cost: 40000,
        desc: "Enables Windows Defender Credential Guard (Virtual Secure Mode isolation of LSA secrets) and triggers automated API network containment on any workstation exhibiting credential theft behavior.",
        mitigations: [
          { attackId: "atk_kerberoast", percent: 60 },
          { attackId: "atk_lateral_smb", percent: 50 }
        ]
      },
      {
        id: "def_laps_tiering",
        name: "Microsoft LAPS Deployment & AD Administrative Tiering",
        shortName: "LAPS & AD Tier 0 Isolation",
        tier: "Identity & Directory Architecture",
        cost: 30000,
        desc: "Enforces unique, randomized local administrator passwords on all workstations via Microsoft LAPS and prevents Domain Admin accounts from ever authenticating on Tier 2 client devices.",
        mitigations: [
          { attackId: "atk_kerberoast", percent: 45 },
          { attackId: "atk_lateral_smb", percent: 65 }
        ]
      },
      {
        id: "def_immutable_backup",
        name: "Air-Gapped Immutable WORM Storage & Rapid Recovery Vault",
        shortName: "Immutable Air-Gapped Backups",
        tier: "Data Protection & Resilience",
        cost: 45000,
        desc: "Stores differential database backups on Write-Once-Read-Many (WORM) hardware storage with out-of-band zero-knowledge keys, completely immune to Active Directory domain compromise.",
        mitigations: [
          { attackId: "atk_ransomware_vss", percent: 85 }
        ]
      },
      {
        id: "def_gmsa_kerberos",
        name: "Group Managed Service Accounts (gMSA) & AES-256 Kerberos",
        shortName: "gMSA & AES Kerberos Policy",
        tier: "Active Directory Hardening",
        cost: 25000,
        desc: "Transforms all legacy SQL and IIS service accounts into 128-character rotating gMSAs, and disables weak RC4-HMAC Kerberos encryption types to make offline hash cracking computationally infeasible.",
        mitigations: [
          { attackId: "atk_kerberoast", percent: 70 }
        ]
      },
      {
        id: "def_canary_vss_lock",
        name: "Ransomware Decoy Honeypots & Immutable VSS Kernel Driver",
        shortName: "Decoy Canaries & VSS Filter",
        tier: "Operating System & Storage",
        cost: 20000,
        desc: "Deploys hidden canary file traps across file shares that terminate offending processes on modification, combined with a kernel mini-filter driver denying any deletion requests targeting VSS snapshots.",
        mitigations: [
          { attackId: "atk_ransomware_vss", percent: 45 },
          { attackId: "atk_lateral_smb", percent: 25 }
        ]
      }
    ]
  },

  // ---------------------------------------------------------------------------
  // SCENARIO 3: CLOUD NATIVE & API BREACH
  // ---------------------------------------------------------------------------
  {
    id: "sc_cloud_breach",
    title: "Cloud Breach 2.0: Serverless BOLA, SSRF & S3 Data Exfiltration",
    shortTitle: "Cloud Breach 2.0 (Serverless & S3)",
    domain: "Cloud Native Microservices & AWS/GCP",
    domainTag: "cloud",
    difficulty: "High",
    budget: 110000,
    potentialDamage: 4200000,
    threatActor: "Scattered Spider / Cloud Heist Group",
    targetAsset: "Serverless Container Fleet & Customer PII S3 Buckets",
    timeWindow: "15 Minutes until Full Data Sync",
    summary: "Attackers target an e-commerce platform's GraphQL and REST APIs. By chaining an authorization flaw (BOLA) with a Server-Side Request Forgery (SSRF) vulnerability in an invoice rendering service, they extract temporary AWS IAM role credentials and drain 4TB of encrypted customer credit data.",
    briefing: "CloudWatch and GuardDuty alarms triggered simultaneously: An external IP began making thousands of sequential GET requests to `/api/v2/orders/{orderId}/pdf`. Buried within the PDF HTML rendering engine was an SSRF bug querying the link-local metadata address `169.254.169.254`. An IAM role named `ProdOrderServiceRole` was compromised, and an unauthorized `aws s3 sync` job was initiated targeting bucket `megashop-customer-vault`.",
    attacks: [
      {
        id: "atk_bola_api",
        name: "Broken Object Level Authorization (BOLA) API Crawl",
        shortName: "BOLA API Endpoint Crawl",
        mitre: "T1190, OWASP API1:2023",
        severity: "critical",
        damage: 1500000,
        stage: "API Access Control Bypass",
        desc: "Adversaries iterate through sequential numeric order IDs without ownership verification, harvesting unmasked customer addresses, phone numbers, and payment references.",
        indicators: "Rapid sequential GET requests to customer endpoints with mismatched user session tokens; high 200 OK volume on administrative resources."
      },
      {
        id: "atk_ssrf_metadata",
        name: "SSRF Extraction of Cloud Metadata (IMDSv1) Secrets",
        shortName: "SSRF Cloud Metadata Theft",
        mitre: "T1552.005, T1078.004",
        severity: "critical",
        damage: 1600000,
        stage: "Cloud Credential Theft",
        desc: "The invoice preview worker fetches `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, extracting ephemeral AWS STS access keys, secret keys, and session tokens.",
        indicators: "Outbound HTTP requests from container pods to 169.254.169.254 without IMDSv2 token headers; API calls using instance credentials from external foreign IP addresses."
      },
      {
        id: "atk_s3_exfil",
        name: "Automated S3 Bucket Replication & Bulk Data Exfiltration",
        shortName: "S3 Bucket Cloud Exfiltration",
        mitre: "T1537, T1567.002",
        severity: "high",
        damage: 1100000,
        stage: "Mass Data Exfiltration",
        desc: "Using the stolen IAM credentials, the adversary invokes `s3:GetObject` and `s3:ListBucket` across all customer archives, piping encrypted records directly to an attacker-owned S3 bucket.",
        indicators: "Spike in S3 egress bandwidth; GuardDuty alert 'Exfiltration:S3/AnomalousBehavior'; sudden spike in GetObject API calls from an unapproved IP."
      }
    ],
    defenses: [
      {
        id: "def_imds_v2",
        name: "Enforce IMDSv2 Session Token & Set Metadata Hop Limit to 1",
        shortName: "Enforce IMDSv2 & Hop Limit 1",
        tier: "Cloud Infrastructure",
        cost: 15000,
        desc: "Mandates IMDSv2 requiring a session-oriented PUT request with `X-aws-ec2-metadata-token` headers, and enforces a network hop limit of 1 so container bridges cannot access host metadata.",
        mitigations: [
          { attackId: "atk_ssrf_metadata", percent: 100 }
        ]
      },
      {
        id: "def_api_auth_gateway",
        name: "Zero-Trust API Gateway Token Scope Claims & Contextual RBAC",
        shortName: "API Gateway Claims & BOLA Shield",
        tier: "API Gateway & Application Security",
        cost: 35000,
        desc: "Inspects JWT claims at the API Gateway level to ensure the requesting user's identity matches the requested resource object ID, completely neutralizing BOLA traversal attacks.",
        mitigations: [
          { attackId: "atk_bola_api", percent: 95 }
        ]
      },
      {
        id: "def_cloud_dlp_guard",
        name: "Cloud DLP S3 Circuit Breaker & GuardDuty Auto-Remediation",
        shortName: "S3 Circuit Breaker & GuardDuty",
        tier: "Data Protection & Incident Response",
        cost: 30000,
        desc: "Configures automated EventBridge rules triggered by GuardDuty S3 anomaly detections to immediately attach an inline explicit DENY IAM policy, severing active exfiltration sessions in seconds.",
        mitigations: [
          { attackId: "atk_s3_exfil", percent: 85 }
        ]
      },
      {
        id: "def_egress_firewall",
        name: "Private VPC NAT Restriction & Egress Proxy Whitelisting",
        shortName: "VPC Egress Filtering & Proxy",
        tier: "Cloud Network Security",
        cost: 20000,
        desc: "Restricts all serverless container worker nodes to private VPC subnets with an egress proxy that forbids direct outbound connections to the internet or non-whitelisted destinations.",
        mitigations: [
          { attackId: "atk_ssrf_metadata", percent: 40 },
          { attackId: "atk_s3_exfil", percent: 45 }
        ]
      },
      {
        id: "def_iam_least_privilege",
        name: "Automated IAM Least-Privilege Policy Engine & Session Lock",
        shortName: "IAM Least-Privilege Engine",
        tier: "Cloud IAM & Governance",
        cost: 25000,
        desc: "Strips broad wildcard permissions (`s3:*`) from compute service roles, enforcing resource ARN restrictions and tying temporary STS credentials strictly to source VPC endpoint IP ranges.",
        mitigations: [
          { attackId: "atk_s3_exfil", percent: 60 },
          { attackId: "atk_bola_api", percent: 25 }
        ]
      }
    ]
  },

  // ---------------------------------------------------------------------------
  // SCENARIO 4: CRITICAL INFRASTRUCTURE / SCADA / OT
  // ---------------------------------------------------------------------------
  {
    id: "sc_scada_grid",
    title: "StuxGrid Zero: Smart Grid SCADA Infiltration & PLC Safety Override",
    shortTitle: "StuxGrid Zero (SCADA / OT Grid)",
    domain: "Industrial Control Systems (ICS/SCADA) & Energy",
    domainTag: "scada",
    difficulty: "Critical",
    budget: 140000,
    potentialDamage: 8000000,
    threatActor: "Sandworm / APT44 Cyber Warfare Group",
    targetAsset: "Substation RTUs, Siemens S7 PLCs & Safety Relays",
    timeWindow: "Immediate Threat to Electrical Turbine Safety",
    summary: "A foreign cyber warfare unit penetrates an electrical power distribution grid. Bridging an unsegmented maintenance laptop into the SCADA Purdue Model Level 2 network, the adversary injects rogue Modbus/TCP write commands and overwrites PLC firmware to force breaker trips and cause physical turbine damage.",
    briefing: "Alert received from the Power Transmission Dispatch Center: Circuit breakers across Substation 7 began opening and closing intermittently. Network captures reveal unexpected Modbus Function Code 05 (Write Single Coil) commands originating from a maintenance contractor jumpbox. HMI screens in the control room show false nominal readings, masking a critical over-frequency condition.",
    attacks: [
      {
        id: "atk_it_ot_pivot",
        name: "Dual-Homed Maintenance Workstation IT/OT Network Pivot",
        shortName: "IT/OT Jumpbox Pivot",
        mitre: "T0886, T0812",
        severity: "high",
        damage: 2000000,
        stage: "Network Boundary Infiltration",
        desc: "Adversaries compromise a contractor's laptop connected to both corporate Wi-Fi and the industrial SCADA subnet, utilizing it as an unmonitored TCP forwarding proxy into Purdue Level 2.",
        indicators: "Anomalous SSH/RDP tunnels between corporate IT IP space and industrial 10.240.x.x SCADA VLANs."
      },
      {
        id: "atk_modbus_inject",
        name: "Modbus/TCP & DNP3 Unauthenticated Command Injection",
        shortName: "Modbus/DNP3 Command Injection",
        mitre: "T0855, T0843",
        severity: "critical",
        damage: 3200000,
        stage: "Industrial Protocol Manipulation",
        desc: "Because legacy Modbus/TCP lacks native cryptographic authentication, attackers forge raw packet payloads commanding substation PLCs to trip primary electrical feeder lines.",
        indicators: "Sudden flood of Modbus Function Code 05/06/16 packets; commands targeting coil addresses 0x0100 through 0x0150."
      },
      {
        id: "atk_plc_firmware",
        name: "Programmable Logic Controller (PLC) Firmware Modification",
        shortName: "PLC Firmware Overwrite",
        mitre: "T0839, T0857",
        severity: "critical",
        damage: 2800000,
        stage: "Physical Equipment Destruction",
        desc: "Attackers upload a rogue ladder logic block that disables turbine speed governing limits while continuing to report normal 3000 RPM telemetry back to human operators.",
        indicators: "Siemens S7 communication protocol diagnostic block downloads; PLC operating state changing from RUN to STOP/PROGRAM."
      }
    ],
    defenses: [
      {
        id: "def_data_diode",
        name: "Unidirectional Hardware Optical Data Diode & Air-Gap",
        shortName: "Hardware Optical Data Diode",
        tier: "Physical & Network Isolation",
        cost: 45000,
        desc: "Installs a physical fiber-optic hardware data diode permitting telemetry to exit the OT network to IT monitoring servers while physically making it impossible for any packet to travel from IT into OT.",
        mitigations: [
          { attackId: "atk_it_ot_pivot", percent: 95 },
          { attackId: "atk_modbus_inject", percent: 40 }
        ]
      },
      {
        id: "def_ot_dpi_firewall",
        name: "Industrial Deep Packet Inspection (DPI) & Protocol Filter",
        shortName: "Industrial DPI Firewall",
        tier: "OT Network Security",
        cost: 35000,
        desc: "Deploys industrial firewalls (Nozomi / Claroty / Fortinet) enforcing deep packet inspection on Modbus/TCP, blocking all 'Write' commands except those signed by certified master HMI IPs.",
        mitigations: [
          { attackId: "atk_modbus_inject", percent: 90 }
        ]
      },
      {
        id: "def_plc_crypto_keyswitch",
        name: "Physical PLC Key-Switch Lock & Cryptographic Firmware Signing",
        shortName: "Physical Key-Switch & Signed Logic",
        tier: "Controller Hardware Hardening",
        cost: 30000,
        desc: "Forces physical keys on all PLCs into 'RUN' mode (preventing remote program modifications over the wire) and enforces PKI cryptographic signature verification on all compiled ladder logic.",
        mitigations: [
          { attackId: "atk_plc_firmware", percent: 100 }
        ]
      },
      {
        id: "def_analog_sis_relays",
        name: "Out-of-Band Hardwired Analog Safety Instrumented Relays (SIS)",
        shortName: "Analog Safety Relays (SIS)",
        tier: "Physical Safety Systems",
        cost: 40000,
        desc: "Independent hardwired analog centrifugal switches and pneumatic pressure relief circuits that automatically cut power if physical thresholds are breached, totally immune to software compromise.",
        mitigations: [
          { attackId: "atk_plc_firmware", percent: 50 },
          { attackId: "atk_modbus_inject", percent: 45 }
        ]
      }
    ]
  },

  // ---------------------------------------------------------------------------
  // SCENARIO 5: CORPORATE WIRELESS & ROGUE AP
  // ---------------------------------------------------------------------------
  {
    id: "sc_wireless_pinedrop",
    title: "Operation PineDrop: Executive Evil Twin & Rogue AP Wiretapping",
    shortTitle: "Operation PineDrop (Wireless Rogue AP)",
    domain: "Enterprise Wi-Fi & Layer-2 Security",
    domainTag: "wireless",
    difficulty: "Moderate",
    budget: 95000,
    potentialDamage: 2800000,
    threatActor: "Corporate Espionage / ShadowPawn Mercenaries",
    targetAsset: "Executive Laptops, Mobile Devices & OIDC SSO Tokens",
    timeWindow: "Active During Annual Board of Directors Meeting",
    summary: "During an annual executive summit at a downtown conference hotel, an adversary concealed a battery-powered rogue access point in the auditorium ceiling. The rogue AP mimics the corporate 802.1X SSID, floods 802.11 deauth frames to force client disconnects, and harvests Microsoft 365 executive credentials via SSL stripping.",
    briefing: "Multiple executive attendees reported unexpected Wi-Fi disconnects and recurring browser security warnings. Wireless spectrum sensors detected an unauthorized transmitter broadcasting BSSID matching the corporate enterprise SSID with maximum transmit power (23 dBm), alongside a continuous stream of spoofed 802.11 deauthentication frames targeting VIP MAC addresses.",
    attacks: [
      {
        id: "atk_evil_twin",
        name: "Evil Twin Rogue AP Broadcast & Probe Response Sniffing",
        shortName: "Evil Twin Rogue AP",
        mitre: "T1040, T1557",
        severity: "high",
        damage: 1000000,
        stage: "Layer-2 Wireless Association Hijacking",
        desc: "The adversary's transmitter responds to probe requests with the corporate SSID 'CORP_EXECUTIVE_SECURE' at high RF power, inducing corporate mobile phones and laptops to associate with the rogue AP.",
        indicators: "Two distinct BSSIDs advertising the identical SSID; anomalous signal strength variance; rogue BSSID with non-corporate OUI manufacturer code."
      },
      {
        id: "atk_deauth_flood",
        name: "802.11 Management Deauthentication Frame Flooding",
        shortName: "802.11 Deauth Flood",
        mitre: "T1498.001",
        severity: "medium",
        damage: 600000,
        stage: "Denial-of-Service / Forced Reconnect",
        desc: "The attacker sends unencrypted 802.11 Type 0 Subtype 12 deauthentication frames spoofing the genuine access point's MAC address, disconnecting clients and driving them onto the evil twin.",
        indicators: "Abnormal spike in deauth frame count (>5,000/min); channel utilization saturation on 2.4 GHz and 5 GHz bands."
      },
      {
        id: "atk_ssl_strip",
        name: "SSL Stripping & Rogue Captive Portal SSO Harvester",
        shortName: "SSL Strip & Fake SSO Portal",
        mitre: "T1557.001, T1566.002",
        severity: "critical",
        damage: 1200000,
        stage: "Credential Harvesting & Session Theft",
        desc: "Once clients connect to the rogue AP, DNS requests are poisoned and HTTP 302 redirects downgrade HTTPS traffic to HTTP, rendering a pixel-perfect fake Microsoft 365 login portal to capture 2FA tokens.",
        indicators: "Clients communicating over unencrypted port 80 for known HTTPS domains; mismatched SSL certificate warnings; DNS responses redirecting to local rogue IP 192.168.1.1."
      }
    ],
    defenses: [
      {
        id: "def_wips_containment",
        name: "Enterprise WIPS Sensor Triangulation & Auto-Containment",
        shortName: "Enterprise WIPS Auto-Containment",
        tier: "Wireless Infrastructure",
        cost: 30000,
        desc: "Dedicated radio frequency sensors continuously sweep channels, instantly triangulating the physical location of rogue APs and transmitting targeted containment frames to neutralize the rogue transmitter.",
        mitigations: [
          { attackId: "atk_evil_twin", percent: 90 },
          { attackId: "atk_deauth_flood", percent: 60 }
        ]
      },
      {
        id: "def_pmf_80211w",
        name: "Enforce 802.11w Protected Management Frames (PMF)",
        shortName: "802.11w PMF Cryptographic Frames",
        tier: "Wireless Protocol Security",
        cost: 15000,
        desc: "Mandates 802.11w Protected Management Frames across all enterprise APs and endpoints, cryptographically signing deauth and disassociation frames to render spoofed deauth packets completely useless.",
        mitigations: [
          { attackId: "atk_deauth_flood", percent: 100 }
        ]
      },
      {
        id: "def_eap_tls_certs",
        name: "WPA3-Enterprise 192-bit Security with Mandatory EAP-TLS",
        shortName: "WPA3-Enterprise EAP-TLS Certs",
        tier: "Identity & Cryptographic Authentication",
        cost: 35000,
        desc: "Replaces user passwords with machine and user X.509 PKI certificates. Devices validate the radius server's corporate CA certificate before associating, making connection to an unauthenticated rogue AP impossible.",
        mitigations: [
          { attackId: "atk_evil_twin", percent: 95 },
          { attackId: "atk_ssl_strip", percent: 50 }
        ]
      },
      {
        id: "def_hsts_cert_pinning",
        name: "Preloaded HSTS, Certificate Pinning & Always-On Zero-Trust VPN",
        shortName: "Preloaded HSTS & Always-On VPN",
        tier: "Host & Browser Security",
        cost: 25000,
        desc: "Forces browsers to reject unencrypted HTTP connections via strict HSTS headers and tunnels all executive network traffic through an encrypted WireGuard/IPsec Zero-Trust tunnel the instant a network connects.",
        mitigations: [
          { attackId: "atk_ssl_strip", percent: 100 }
        ]
      }
    ]
  },

  // ---------------------------------------------------------------------------
  // SCENARIO 6: CLOUD KUBERNETES & LINUX KERNEL ESCAPE
  // ---------------------------------------------------------------------------
  {
    id: "sc_kernel_escape",
    title: "Kernel Escape: Kubernetes Container Breakout & Host Hijacking",
    shortTitle: "Kernel Escape (K8s & Linux)",
    domain: "Linux Kernel Security & Cloud-Native Containers",
    domainTag: "linux",
    difficulty: "High",
    budget: 125000,
    potentialDamage: 4200000,
    threatActor: "TeamTNT / FIN7 Cloud Operators",
    targetAsset: "Kubernetes Worker Nodes, Host Kernel & Tenant Secrets",
    timeWindow: "25 Minutes until Entire Cluster Takeover",
    summary: "A malicious tenant in a shared multi-tenant Kubernetes cluster exploits a public-facing container RCE. Leveraging the Linux Dirty Pipe kernel vulnerability (CVE-2022-0847) and a misconfigured Docker socket mount, they break out of the container namespace, achieve root on the underlying Linux host, and dump all secrets.",
    briefing: "Falco runtime alarms triggered in namespace `production-apps`: Process `python3` spawned a `/bin/bash` shell inside a web app pod. 90 seconds later, an attempt to overwrite `/etc/passwd` on the underlying Linux node host was detected using a pipe buffer splice exploit. The container was found to have the host's `/var/run/docker.sock` mounted, granting unrestricted host API control.",
    attacks: [
      {
        id: "atk_container_rce",
        name: "Public Container Ingress Remote Code Execution (RCE)",
        shortName: "Container Ingress RCE",
        mitre: "T1190, T1059",
        severity: "high",
        damage: 900000,
        stage: "Initial Ingress & Foothold",
        desc: "Adversaries exploit an untrusted deserialization bug in a web pod's Python application to obtain an interactive reverse shell inside the container namespace.",
        indicators: "Spawned `/bin/bash` or `/bin/sh` processes under web server user UID 1000; unexpected outbound connection to dynamic DNS IP on port 4444."
      },
      {
        id: "atk_dirtypipe_escape",
        name: "Linux Dirty Pipe (CVE-2022-0847) Kernel Privilege Escalation",
        shortName: "Dirty Pipe Kernel Escape",
        mitre: "T1068, T1611",
        severity: "critical",
        damage: 1800000,
        stage: "Container Escape & Host Rooting",
        desc: "Exploits uninitialized flags in Linux kernel pipe buffers to overwrite read-only page cache files on the host, modifying `/etc/passwd` to create a root UID 0 user on the host node.",
        indicators: "Falco alert 'Write below etc in host'; abnormal syscall sequences involving `splice` and `pipe2` with read-only target files."
      },
      {
        id: "atk_docker_sock",
        name: "Mounted Docker Socket Exploitation & Cluster Secret Dump",
        shortName: "Docker Socket Host Takeover",
        mitre: "T1611, T1552",
        severity: "critical",
        damage: 1500000,
        stage: "Cluster-Wide Lateral Compromise",
        desc: "The attacker talks to the mounted `/var/run/docker.sock` to spin up a privileged container with the host root filesystem mounted at `/host`, dumping kubelet tokens and cross-tenant secrets.",
        indicators: "Docker daemon receiving API commands to create privileged containers with host PID and IPC namespaces; kubelet service account token extraction."
      }
    ],
    defenses: [
      {
        id: "def_seccomp_apparmor",
        name: "Strict Seccomp-BPF Syscall Filter & AppArmor Profiles",
        shortName: "Strict Seccomp-BPF & AppArmor",
        tier: "Linux Kernel Hardening",
        cost: 25000,
        desc: "Enforces strict Seccomp-BPF profiles dropping dangerous syscalls (`splice`, `vmsplice`, `ptrace`, `bpf`) from user containers, preemptively neutralizing Dirty Pipe exploit execution.",
        mitigations: [
          { attackId: "atk_container_rce", percent: 40 },
          { attackId: "atk_dirtypipe_escape", percent: 85 }
        ]
      },
      {
        id: "def_livepatch_kernel",
        name: "Automated Linux Kernel Livepatching (Kpatch / Canonical Livepatch)",
        shortName: "Automated Kernel Livepatching",
        tier: "Host OS Maintenance",
        cost: 30000,
        desc: "Deploys rebootless kernel livepatches across all cluster worker nodes within minutes of CVE publication, directly repairing flawed pipe buffer structures in running memory.",
        mitigations: [
          { attackId: "atk_dirtypipe_escape", percent: 100 }
        ]
      },
      {
        id: "def_rootless_gvisor",
        name: "gVisor User-Space Sandbox Runtime & Rootless Containers",
        shortName: "gVisor Sandbox Runtime",
        tier: "Container Isolation Virtualization",
        cost: 40000,
        desc: "Executes containers under gVisor's `runsc` virtualized user-space kernel. Syscalls are trapped in user space and never directly reach the host Linux kernel, eliminating kernel breakouts.",
        mitigations: [
          { attackId: "atk_container_rce", percent: 60 },
          { attackId: "atk_dirtypipe_escape", percent: 95 },
          { attackId: "atk_docker_sock", percent: 70 }
        ]
      },
      {
        id: "def_socket_proxy_mtls",
        name: "Eradicate Docker Socket Mounts & Enforce Admission Controller",
        shortName: "OPA Gatekeeper & No Docker Socket",
        tier: "Kubernetes Policy & Admission Control",
        cost: 20000,
        desc: "Deploys OPA Gatekeeper / Kyverno policies that strictly block any pod specification containing host volume mounts or `/var/run/docker.sock`, completely eliminating host API hijacking.",
        mitigations: [
          { attackId: "atk_docker_sock", percent: 100 }
        ]
      },
      {
        id: "def_falco_runtime",
        name: "eBPF Falco Cloud-Native Threat Detection & Automated Process Kill",
        shortName: "eBPF Falco Auto-Kill",
        tier: "Cloud-Native Runtime Security",
        cost: 25000,
        desc: "Hooks into kernel tracepoints via eBPF; immediately detects unauthorized shell spawning inside pods and sends SIGKILL to the offending PID within 2 milliseconds.",
        mitigations: [
          { attackId: "atk_container_rce", percent: 65 },
          { attackId: "atk_docker_sock", percent: 50 }
        ]
      }
    ]
  },
  // ---------------------------------------------------------------------------
  // SCENARIO 7: OWASP TOP 10 & CLOUD API BREACH
  // ---------------------------------------------------------------------------
  {
    id: "sc_ecommerce_owasp",
    title: "Operation BrokenToken: E-Commerce Cloud API & OWASP Top 10 Infiltration",
    shortTitle: "Operation BrokenToken (OWASP API)",
    domain: "Cloud Microservices & OWASP Web App Tier",
    domainTag: "owasp",
    difficulty: "High",
    budget: 160000,
    potentialDamage: 5200000,
    threatActor: "FIN7 / Magecart Cyber Syndicate",
    targetAsset: "Customer Auth0/JWT Gateway, Microservices API & Cart Checkout",
    timeWindow: "45 Minutes before Automated Exfiltration",
    summary: "A financial cybercrime syndicate launches a coordinated OWASP Top 10 assault against a global retailer's cloud infrastructure. Exploiting Broken Access Control (IDOR), they harvest customer records, trigger Server-Side Request Forgery (SSRF) against AWS IMDS to steal cloud IAM tokens, compromise CI/CD software integrity with poisoned dependencies, and tamper with audit logs to conceal the breach.",
    briefing: "At 18:15 UTC, the SOC flagged an abnormal volume of API requests to /api/v1/users/{id} cycling through sequential numeric customer IDs. Simultaneously, AWS GuardDuty alerted on an EC2 instance querying the Instance Metadata Service (169.254.169.254) and attempting STS AssumeRole calls. Build runners in the CI/CD pipeline were observed fetching untrusted npm packages containing obfuscated post-install scripts.",
    attacks: [
      {
        id: "atk_broken_access",
        name: "Broken Access Control (IDOR & Tenant Boundary Bypass)",
        shortName: "IDOR Access Control",
        mitre: "T1548, T1078",
        severity: "critical",
        damage: 1500000,
        stage: "Authorization Subversion & Enumeration",
        desc: "Adversary alters numeric account IDs in authenticated REST requests to siphoning billing profiles, saved credit cards, and addresses of other tenants.",
        indicators: "Rapid sequence of HTTP 200 responses to /api/v1/users/{id} from a single Bearer token; dc(user_id) > 100 in 5 minutes."
      },
      {
        id: "atk_ssrf_imds",
        name: "Server-Side Request Forgery (SSRF Cloud Metadata Theft)",
        shortName: "SSRF IMDS Metadata",
        mitre: "T1190, T1552.005",
        severity: "critical",
        damage: 1800000,
        stage: "Cloud Perimeter Pivot & Credential Access",
        desc: "Exploiting an image-rendering URL webhook parameter to query AWS IMDS (169.254.169.254/latest/meta-data/iam/security-credentials), stealing EC2 IAM temporary role keys.",
        indicators: "Outbound HTTP requests from web servers to 169.254.169.254; GuardDuty alert IAMUser/InstanceCredentialExfiltration."
      },
      {
        id: "atk_integrity_poison",
        name: "Software & Data Integrity Failures (CI/CD Supply Chain Poisoning)",
        shortName: "Supply Chain Poisoning",
        mitre: "T1195.002, T1059",
        severity: "critical",
        damage: 1100000,
        stage: "Build Pipeline Infection",
        desc: "Attackers inject a backdoored npm dependency into the frontend build pipeline, deploying client-side Magecart card skimming scripts directly into the checkout bundle.",
        indicators: "Unsigned package installed during npm install; unexpected outbound network connections from build container to unfamiliar IP."
      },
      {
        id: "atk_logging_blindspot",
        name: "Security Logging and Monitoring Failures (Stealth Log Evasion)",
        shortName: "Logging Failures",
        mitre: "T1562.002, T1070",
        severity: "high",
        damage: 800000,
        stage: "Defense Evasion & Blindspotting",
        desc: "Attackers flood error logs with garbage exceptions to trigger automated log truncation and kill local syslog forwarders, hiding their lateral movements.",
        indicators: "Sudden gap in web server log forwarding to SIEM; log ingestion volume drop of 80% on primary payment cluster."
      }
    ],
    defenses: [
      {
        id: "def_rbac_abac",
        name: "Centralized ABAC/RBAC API Enforcement Engine",
        shortName: "Centralized ABAC/RBAC",
        tier: "Application Security & IAM",
        cost: 32000,
        desc: "Deploys Open Policy Agent (OPA) middleware to evaluate user context, resource ownership, and tenant claims on every API route before executing queries.",
        mitigations: [
          { attackId: "atk_broken_access", percent: 85 },
          { attackId: "atk_ssrf_imds", percent: 20 }
        ]
      },
      {
        id: "def_imdsv2_proxy",
        name: "Mandatory IMDSv2 Token Enforcement & Webhook Egress Proxy",
        shortName: "IMDSv2 & Egress Proxy",
        tier: "Cloud Infrastructure",
        cost: 26000,
        desc: "Enforces AWS IMDSv2 requiring session tokens with hop-limit=1 across all cloud workloads and routes external URL fetching through an isolated egress proxy.",
        mitigations: [
          { attackId: "atk_ssrf_imds", percent: 85 },
          { attackId: "atk_broken_access", percent: 15 }
        ]
      },
      {
        id: "def_slsa_signing",
        name: "Cryptographic SLSA Build Signing & Automated Dependency Pinning",
        shortName: "SLSA Signing & SBOM",
        tier: "DevSecOps & Supply Chain",
        cost: 38000,
        desc: "Enforces cryptographic artifact signing via Sigstore/Cosign, verifies package hash locks, and scans all dependencies against known vulnerability feeds.",
        mitigations: [
          { attackId: "atk_integrity_poison", percent: 90 }
        ]
      },
      {
        id: "def_worm_siem",
        name: "Immutable WORM SIEM Streaming & Heartbeat Tamper Alerting",
        shortName: "WORM SIEM & Heartbeat",
        tier: "SOC Telemetry & SIEM",
        cost: 34000,
        desc: "Streams all security audit logs over mTLS to an immutable Write-Once-Read-Many cloud storage vault with real-time heartbeat failure alerting.",
        mitigations: [
          { attackId: "atk_logging_blindspot", percent: 90 },
          { attackId: "atk_broken_access", percent: 20 }
        ]
      },
      {
        id: "def_dast_api_shield",
        name: "Adaptive API Security Gateway & Schema Conformance Shield",
        shortName: "API Gateway Shield",
        tier: "API Perimeter",
        cost: 30000,
        desc: "Inspects API payloads against OpenAPI specifications in real time, terminating requests with non-conforming parameters or anomalous resource iterations.",
        mitigations: [
          { attackId: "atk_broken_access", percent: 40 },
          { attackId: "atk_ssrf_imds", percent: 40 }
        ]
      }
    ]
  },

  // ---------------------------------------------------------------------------
  // SCENARIO 8: DATABASE BREACH & BLIND SQLi
  // ---------------------------------------------------------------------------
  {
    id: "sc_database_heist",
    title: "Project DeepQuery: Critical Database Breach, Blind SQLi & DBA Privilege Escalation",
    shortTitle: "Project DeepQuery (Database Breach)",
    domain: "Core Relational Database Tier & Enterprise Data Warehouse",
    domainTag: "database",
    difficulty: "Critical",
    budget: 145000,
    potentialDamage: 6000000,
    threatActor: "APT29 / Midnight Blizzard Variant",
    targetAsset: "Oracle RAC & PostgreSQL Enterprise Customer Core Database",
    timeWindow: "30 Minutes until Full Table Dump",
    summary: "State-sponsored cyber espionage operators penetrate the corporate network and target the core enterprise relational databases. Leveraging Time-Based Blind SQL Injection, they map system catalogs, escalate database privileges to DBA superuser via vulnerable stored procedures, and establish direct unauthorized connections to siphon encrypted customer credit card vaults.",
    briefing: "At 02:20 AM, database APM alerted on persistent 5-second query latency anomalies on legacy customer search endpoints. Further investigation revealed a threat actor executing stacked SQL queries, abusing a SECURITY DEFINER function to grant the application account SUPERUSER privileges, and configuring PostgreSQL pg_hba.conf to allow remote TCP connections from external hosts.",
    attacks: [
      {
        id: "atk_blind_sqli",
        name: "Blind SQL Injection (Time-Based & Boolean Inference Extraction)",
        shortName: "Blind SQL Injection",
        mitre: "T1190, T1083",
        severity: "critical",
        damage: 1800000,
        stage: "Initial Exploitation & Data Bisection",
        desc: "Exploiting dynamic SQL in backend reporting procedures with time-based delay functions (pg_sleep(5), WAITFOR DELAY) to extract database contents character-by-character.",
        indicators: "Persistent 5000ms latency on search endpoints; database slow query log showing hundreds of calls to pg_sleep()."
      },
      {
        id: "atk_db_priv_esc",
        name: "Database Privilege Escalation (DBA Role Abuse & UDF Exploitation)",
        shortName: "DB Privilege Escalation",
        mitre: "T1068, T1548",
        severity: "critical",
        damage: 1900000,
        stage: "Privilege Escalation to Superuser",
        desc: "Exploiting search_path vulnerabilities in an administrative SECURITY DEFINER function to execute ALTER ROLE app_user WITH SUPERUSER.",
        indicators: "Database audit log event: ALTER ROLE app_user SUPERUSER; creation of new database administrative accounts."
      },
      {
        id: "atk_db_enum",
        name: "Database Enumeration (Catalog Metadata & Schema Siphoning)",
        shortName: "Database Enumeration",
        mitre: "T1082, T1083",
        severity: "medium",
        damage: 900000,
        stage: "Schema & Credential Mapping",
        desc: "Querying information_schema.tables, information_schema.columns, and pg_shadow to catalog sensitive tables and dump password hashes.",
        indicators: "High volume of queries against information_schema and pg_catalog views from non-DBA connection sessions."
      },
      {
        id: "atk_unauth_db",
        name: "Unauthorized Database Access (Direct TCP Port 5432 Connection)",
        shortName: "Unauthorized DB Access",
        mitre: "T1078, T1021.006",
        severity: "critical",
        damage: 1400000,
        stage: "Direct Connection Hijack",
        desc: "Opening direct TCP connections to PostgreSQL port 5432 from an external command server using the newly minted superuser credentials.",
        indicators: "Inbound connection to port 5432 originating outside internal VPC CIDR block; pg_hba.conf host rule modified."
      }
    ],
    defenses: [
      {
        id: "def_dam_profiler",
        name: "Database Activity Monitoring (DAM) with Behavioral ML Profiling",
        shortName: "Database Activity Monitor (DAM)",
        tier: "Database Security",
        cost: 36000,
        desc: "Inspects 100% of SQL traffic in real time at the protocol level (IBM Guardium / Imperva DAM), alerting on schema catalog harvesting and blocking anomalous superuser grants.",
        mitigations: [
          { attackId: "atk_db_priv_esc", percent: 80 },
          { attackId: "atk_db_enum", percent: 85 },
          { attackId: "atk_blind_sqli", percent: 35 }
        ]
      },
      {
        id: "def_param_sql",
        name: "Parameterized Prepared Statements & Query Statement Timeouts",
        shortName: "Parameterized SQL & Timeouts",
        tier: "Application Logic & Database",
        cost: 25000,
        desc: "Refactors dynamic SQL to parameterized PreparedStatement calls and sets statement_timeout=2000ms, completely neutralizing time-based blind SQLi delays.",
        mitigations: [
          { attackId: "atk_blind_sqli", percent: 85 },
          { attackId: "atk_db_enum", percent: 30 }
        ]
      },
      {
        id: "def_polp_dba",
        name: "Principle of Least Privilege (PoLP) & Function search_path Hardening",
        shortName: "PoLP & Stored Procedure Lock",
        tier: "Database Configuration",
        cost: 22000,
        desc: "Strips DDL and superuser privileges from all application users and locks SECURITY DEFINER functions with strict immutable search_path settings.",
        mitigations: [
          { attackId: "atk_db_priv_esc", percent: 85 }
        ]
      },
      {
        id: "def_tde_masking",
        name: "Dynamic Data Masking & Transparent Column Encryption (TDE)",
        shortName: "TDE & Data Masking",
        tier: "Data Protection",
        cost: 32000,
        desc: "Enforces AES-256 column-level encryption for credit cards and PII with dynamic data masking for unprivileged query results.",
        mitigations: [
          { attackId: "atk_blind_sqli", percent: 45 },
          { attackId: "atk_db_enum", percent: 40 }
        ]
      },
      {
        id: "def_pam_ephemeral",
        name: "Zero-Trust PAM Gateway with Ephemeral JIT Database Credentials",
        shortName: "Zero-Trust PAM & Private Subnets",
        tier: "Identity & Network Architecture",
        cost: 30000,
        desc: "Places databases in air-gapped private subnets with no public ingress and requires HashiCorp Vault to generate dynamic, short-lived 15-minute connection tokens.",
        mitigations: [
          { attackId: "atk_unauth_db", percent: 95 },
          { attackId: "atk_db_priv_esc", percent: 25 }
        ]
      }
    ]
  },

  // ---------------------------------------------------------------------------
  // SCENARIO 9: STORAGE SECURITY & DESTUCTIVE WIPER SABOTAGE
  // ---------------------------------------------------------------------------
  {
    id: "sc_storage_sabotage",
    title: "Operation BlackVault: Storage Tampering, Wiper Destruction & Cloud Exfiltration",
    shortTitle: "Operation BlackVault (Storage Wiper)",
    domain: "Enterprise SAN, Multi-Cloud Storage Buckets & Backup Infrastructure",
    domainTag: "storage",
    difficulty: "Critical",
    budget: 180000,
    potentialDamage: 8500000,
    threatActor: "Sandworm / HermeticWiper Sabotage Cell",
    targetAsset: "Multi-Cloud Object Storage (S3/GCS), SAN LUNs & Disaster Recovery Snapshots",
    timeWindow: "25 Minutes before Disk Zeroing",
    summary: "A nation-state destructive sabotage unit compromises cloud storage credentials and SAN administration consoles. They systematically corrupt transactional ledgers through silent data tampering, initiate high-speed exfiltration of classified engineering blueprints via Rclone, and prime wiper routines to delete all volume shadow copies and snapshot catalogs.",
    briefing: "Urgent red alert from the Storage Operations Center: S3 bucket policies across the primary data lake were altered to remove encryption headers. Concurrently, an outbound transfer session to an offshore IPFS node initiated transferring 120 GB of archived financial databases. On-premise storage arrays reported snapshot retention policies being modified to 0 days, followed by vssadmin delete shadows commands executed across core hypervisors.",
    attacks: [
      {
        id: "atk_unauth_storage",
        name: "Unauthorized Data Access & Misconfigured Bucket Harvesting",
        shortName: "Unauthorized Storage Access",
        mitre: "T1078, T1552",
        severity: "critical",
        damage: 1700000,
        stage: "Cloud Storage Container Breach",
        desc: "Attackers discover cloud storage buckets with over-permissive IAM policies, harvesting customer archives and configuration secrets.",
        indicators: "Unusual GetObject API calls from anonymous or newly created IAM roles; CloudTrail alert S3BucketPublicRead."
      },
      {
        id: "atk_data_tamper",
        name: "Data Tampering (Silent Ledger Corruption & Bit-Flipping)",
        shortName: "Data Tampering",
        mitre: "T1565.001, T1565.002",
        severity: "critical",
        damage: 2200000,
        stage: "Integrity Destruction & Ledger Modification",
        desc: "Adversaries overwrite transactional ledger files and patient medical archives, altering values without updating checksum verification tables.",
        indicators: "File Integrity Monitoring (FIM) alerts detecting SHA-256 hash mismatches on stored archives; modified timestamps without audit logs."
      },
      {
        id: "atk_data_exfil",
        name: "High-Speed Cloud Data Exfiltration (Encrypted Rclone to Mega)",
        shortName: "Data Exfiltration",
        mitre: "T1567.002, T1048",
        severity: "critical",
        damage: 2100000,
        stage: "Bulk Data Exfiltration",
        desc: "Staging proprietary design documents into encrypted 7-Zip archives and streaming them via Rclone to decentralized cloud storage nodes at 400 Mbps.",
        indicators: "Sudden spike in outbound HTTPS egress traffic to mega.nz and transfer.sh; process execution of rclone.exe."
      },
      {
        id: "atk_data_destruct",
        name: "Malicious Data Destruction (HermeticWiper Snapshot Erasure)",
        shortName: "Data Destruction",
        mitre: "T1485, T1490, T1561",
        severity: "critical",
        damage: 2500000,
        stage: "Catastrophic Disk & Backup Wiping",
        desc: "Executing low-level raw disk zeroing routines (MBR overwrite) and issuing cloud API commands to permanently purge all storage snapshots and backup vaults.",
        indicators: "Sysmon Event ID 1: vssadmin delete shadows /all /quiet; AWS CloudTrail: DeleteSnapshot, DeleteVault; mass I/O raw disk write errors."
      }
    ],
    defenses: [
      {
        id: "def_s3_object_lock",
        name: "S3 Object Lock Compliance Mode & Immutable WORM Storage",
        shortName: "S3 Object Lock WORM",
        tier: "Cloud Storage Architecture",
        cost: 38000,
        desc: "Enforces S3 Object Lock in Compliance Mode; prevents objects from being overwritten or deleted by any user (including root) for the duration of the retention period.",
        mitigations: [
          { attackId: "atk_data_destruct", percent: 85 },
          { attackId: "atk_data_tamper", percent: 80 }
        ]
      },
      {
        id: "def_cloud_dlp",
        name: "Real-Time Cloud DLP & Outbound Bandwidth Anomaly Interceptor",
        shortName: "Cloud DLP & Egress Interceptor",
        tier: "Data Protection & Network",
        cost: 32000,
        desc: "Scans storage objects for sensitive PII/keys using Amazon Macie and automatically terminates network connections exceeding 500MB outbound bursts to unauthorized domains.",
        mitigations: [
          { attackId: "atk_data_exfil", percent: 85 },
          { attackId: "atk_unauth_storage", percent: 35 }
        ]
      },
      {
        id: "def_airgap_vault",
        name: "Air-Gapped Immutable Offline Backup Replication Vault",
        shortName: "Air-Gapped Offline Vault",
        tier: "Business Continuity & Disaster Recovery",
        cost: 45000,
        desc: "Replicates snapshots daily to an isolated, physically separated immutable cloud account with zero network routability and manual multi-key physical access.",
        mitigations: [
          { attackId: "atk_data_destruct", percent: 90 },
          { attackId: "atk_data_tamper", percent: 45 }
        ]
      },
      {
        id: "def_quorum_auth",
        name: "Multi-Party Quorum Authorization (M-of-N Approval) for Storage APIs",
        shortName: "M-of-N Quorum Approval",
        tier: "Storage Governance",
        cost: 25000,
        desc: "Requires cryptographic approval from at least two designated security executives before destructive API calls (DeleteSnapshot, DeleteBucket) can execute.",
        mitigations: [
          { attackId: "atk_data_destruct", percent: 75 },
          { attackId: "atk_unauth_storage", percent: 40 }
        ]
      },
      {
        id: "def_hsm_envelope",
        name: "Hardware Security Module (HSM) Key Management & Auto-Killswitch",
        shortName: "HSM Keys & Killswitch",
        tier: "Cryptography & Host Security",
        cost: 40000,
        desc: "Encrypts all storage volumes using keys stored in FIPS 140-3 Level 3 HSMs; instantly revokes key material if unauthorized disk wiping activity is detected.",
        mitigations: [
          { attackId: "atk_unauth_storage", percent: 70 },
          { attackId: "atk_data_tamper", percent: 50 },
          { attackId: "atk_data_exfil", percent: 40 }
        ]
      }
    ]
  },

  // ---------------------------------------------------------------------------
  // SCENARIO 10: EDGE GATEWAY DESYNC & HTTP REQUEST SMUGGLING
  // ---------------------------------------------------------------------------
  {
    id: "sc_web_smuggling",
    title: "Desync Zero: HTTP Request Smuggling, CSRF & Edge Gateway Evasion",
    shortTitle: "Desync Zero (Request Smuggling)",
    domain: "Edge Application Delivery Controllers & Web Frontends",
    domainTag: "other-web",
    difficulty: "High",
    budget: 140000,
    potentialDamage: 4400000,
    threatActor: "RedCurl Cyber Espionage Brokers",
    targetAsset: "Edge Reverse Proxies, Load Balancers & Enterprise SSO Portal",
    timeWindow: "35 Minutes until SSO Session Poisoning",
    summary: "Cyber espionage operators target an enterprise edge reverse proxy architecture using HTTP Request Smuggling (CL.TE / TE.CL). They desynchronize HTTP pipelines to hijack authenticated executive session cookies, deliver Cross-Site Request Forgery (CSRF) payloads to modify administrative settings, and evade WAF input filters using chunked encoding obfuscation.",
    briefing: "SOC web telemetry flagged anomalous HTTP pipelining requests directed at the company's edge reverse proxies. Threat actors submitted conflicting Content-Length and Transfer-Encoding headers, poisoning the keep-alive socket queue. Shortly after, administrative accounts showed password modification events originating from cross-site form submissions lacking anti-CSRF token verification.",
    attacks: [
      {
        id: "atk_http_smuggle",
        name: "HTTP Request Smuggling (CL.TE & TE.CL Proxy Desynchronization)",
        shortName: "Request Smuggling",
        mitre: "T1190, T1557",
        severity: "critical",
        damage: 1600000,
        stage: "Pipeline Desynchronization & Poisoning",
        desc: "Exploiting discrepancies between front-end reverse proxy and backend server header parsing to prepend malicious requests to subsequent client connections.",
        indicators: "Requests containing both Content-Length and Transfer-Encoding headers; sudden spike in HTTP 400/405 errors on backend microservices."
      },
      {
        id: "atk_web_csrf",
        name: "Cross-Site Request Forgery (CSRF Authenticated State Manipulation)",
        shortName: "CSRF State Manipulation",
        mitre: "T1189, T1566.002",
        severity: "high",
        damage: 1100000,
        stage: "Client-Side Forged Action Execution",
        desc: "Luring authenticated corporate administrators to an external trap page that submits hidden cross-origin POST requests to reset admin credentials.",
        indicators: "POST requests to /admin/change-email with foreign Origin headers; missing or invalid anti-CSRF tokens."
      },
      {
        id: "atk_filter_evasion",
        name: "Input Filtering & WAF Evasion (Chunked Encoding Normalization Bypass)",
        shortName: "Input Filter Evasion",
        mitre: "T1190, T1027",
        severity: "high",
        damage: 800000,
        stage: "Perimeter Shield Subversion",
        desc: "Splitting malicious attack payloads across chunked transfer boundaries and using comment interleaving to bypass edge WAF regex signatures.",
        indicators: "Payloads featuring fragmented chunked encoding (Transfer-Encoding: chunked); WAF protocol anomaly inspection warnings."
      },
      {
        id: "atk_vulnerable_mid",
        name: "Vulnerable & Outdated Web Components (Legacy Middleware Exploit)",
        shortName: "Vulnerable Middleware",
        mitre: "T1195.002, T1190",
        severity: "critical",
        damage: 900000,
        stage: "Remote Code Execution via Library",
        desc: "Triggering a known Remote Code Execution vulnerability in an unpatched legacy reverse proxy caching module to gain shell access.",
        indicators: "Known CVE exploit signature matched in HTTP request headers; unexpected child process spawned by proxy daemon."
      }
    ],
    defenses: [
      {
        id: "def_http2_strict",
        name: "End-to-End HTTP/2 & Strict RFC 7230 Stream Normalization",
        shortName: "End-to-End HTTP/2",
        tier: "Edge Protocol Architecture",
        cost: 28000,
        desc: "Mandates HTTP/2 framing end-to-end between clients, reverse proxies, and backend servers, dropping any request containing conflicting CL/TE headers.",
        mitigations: [
          { attackId: "atk_http_smuggle", percent: 90 },
          { attackId: "atk_filter_evasion", percent: 35 }
        ]
      },
      {
        id: "def_samesite_tokens",
        name: "SameSite=Strict Cookie Enforcement & Cryptographic Anti-CSRF Tokens",
        shortName: "SameSite=Strict & CSRF Tokens",
        tier: "Application Security & Cookies",
        cost: 18000,
        desc: "Configures all session cookies with SameSite=Strict and enforces cryptographically signed per-session anti-CSRF tokens on every state-changing route.",
        mitigations: [
          { attackId: "atk_web_csrf", percent: 95 }
        ]
      },
      {
        id: "def_ng_waf_decode",
        name: "Next-Gen WAF with Deep Protocol Decoding & Anti-Evasion Engine",
        shortName: "Next-Gen WAF Anti-Evasion",
        tier: "Perimeter Security",
        cost: 35000,
        desc: "Deploys an AI-powered NG-WAF that fully normalizes and reassembles chunked HTTP streams before applying deep inspection rules, preventing filter bypasses.",
        mitigations: [
          { attackId: "atk_filter_evasion", percent: 85 },
          { attackId: "atk_http_smuggle", percent: 45 },
          { attackId: "atk_vulnerable_mid", percent: 40 }
        ]
      },
      {
        id: "def_sca_virtual_patch",
        name: "Automated Software Composition Analysis (SCA) & Virtual Patching",
        shortName: "Automated SCA & Virtual Patching",
        tier: "CI/CD & Virtual Patching",
        cost: 34000,
        desc: "Scans edge middleware dependencies continuously for known CVEs and deploys edge virtual patching rules within 60 minutes of vulnerability disclosure.",
        mitigations: [
          { attackId: "atk_vulnerable_mid", percent: 90 }
        ]
      },
      {
        id: "def_strict_csp_sri",
        name: "Strict Content Security Policy (CSP Level 3) & Subresource Integrity",
        shortName: "Strict CSP & SRI",
        tier: "Frontend Hardening",
        cost: 25000,
        desc: "Implements strict nonce-based CSP Level 3 and mandates Subresource Integrity (SRI) on all external web scripts, preventing client-side script tampering.",
        mitigations: [
          { attackId: "atk_web_csrf", percent: 30 },
          { attackId: "atk_filter_evasion", percent: 35 }
        ]
      }
    ]
  }
];

// =============================================================================
// ASSESSMENT ENGINE STATE MANAGEMENT
// =============================================================================

let currentAppMode = "learning"; // 'learning' | 'assessment'
let currentScenarioId = "sc_fintech_ddos";
let activeScenario = SCENARIOS_DATA[0];

// User Allocations State
let scenarioAllocations = {}; // { scenarioId: { activeDefenses: Set, logs: [] } }

// Simulation Runtime State
let isSimulating = false;
let simulationStage = 0;
let simulationInterval = null;

// =============================================================================
// INITIALIZATION & MODE SWITCHING
// =============================================================================

document.addEventListener("DOMContentLoaded", () => {
  initAssessmentMode();
});

function initAssessmentMode() {
  // Initialize allocation records for each scenario
  SCENARIOS_DATA.forEach(sc => {
    if (!scenarioAllocations[sc.id]) {
      scenarioAllocations[sc.id] = {
        activeDefenses: new Set(),
        logs: [
          {
            time: getFormattedTimestamp(),
            type: "info",
            text: `[INCIDENT BRIEFING ACTIVATED] Scenario "${sc.shortTitle}" initialized. Defense Budget allocated: $${sc.budget.toLocaleString()}.`
          }
        ]
      };
    }
  });

  // Setup mode toggle buttons
  const btnLearning = document.getElementById("btn-mode-learning");
  const btnAssessment = document.getElementById("btn-mode-assessment");
  const btnGlossary = document.getElementById("btn-mode-glossary");
  const btnQuiz = document.getElementById("btn-mode-quiz");

  if (btnLearning) {
    btnLearning.addEventListener("click", () => switchAppMode("learning"));
  }
  if (btnAssessment) {
    btnAssessment.addEventListener("click", () => switchAppMode("assessment"));
  }
  if (btnGlossary) {
    btnGlossary.addEventListener("click", () => switchAppMode("glossary"));
  }
  if (btnQuiz) {
    btnQuiz.addEventListener("click", () => switchAppMode("quiz"));
  }

  // Parse hash to see if assessment or glossary mode was requested
  parseAssessmentUrlState();

  // Render initial assessment components
  renderScenarioSelector();
  loadScenario(currentScenarioId, false);
}

function parseAssessmentUrlState() {
  const hash = window.location.hash.replace("#", "");
  if (hash.startsWith("assessment")) {
    const parts = hash.split("?");
    if (parts.length > 1) {
      const params = new URLSearchParams(parts[1]);
      const scId = params.get("scenario");
      if (scId && SCENARIOS_DATA.some(s => s.id === scId)) {
        currentScenarioId = scId;
      }
    }
    switchAppMode("assessment", false);
  } else if (hash.startsWith("glossary")) {
    switchAppMode("glossary", false);
  } else if (hash.startsWith("quiz")) {
    switchAppMode("quiz", false);
  } else if (currentAppMode !== "learning") {
    switchAppMode("learning", false);
  }
}

window.addEventListener("hashchange", () => {
  parseAssessmentUrlState();
});

function switchAppMode(newMode, updateHash = true) {
  currentAppMode = newMode;

  const btnLearning = document.getElementById("btn-mode-learning");
  const btnAssessment = document.getElementById("btn-mode-assessment");
  const btnGlossary = document.getElementById("btn-mode-glossary");
  const btnQuiz = document.getElementById("btn-mode-quiz");

  const learningLayout = document.getElementById("learning-layout");
  const assessmentLayout = document.getElementById("assessment-layout");
  const glossaryLayout = document.getElementById("glossary-layout");
  const quizLayout = document.getElementById("quiz-layout");

  const learningMetrics = document.getElementById("learning-metrics");
  const assessmentMetrics = document.getElementById("assessment-metrics");
  const glossaryMetrics = document.getElementById("glossary-metrics");
  const quizMetrics = document.getElementById("quiz-metrics");

  // Reset active classes
  [btnLearning, btnAssessment, btnGlossary, btnQuiz].forEach(btn => {
    if (btn) {
      btn.classList.remove("active");
      btn.setAttribute("aria-selected", "false");
    }
  });

  // Hide all layouts
  if (learningLayout) learningLayout.style.display = "none";
  if (assessmentLayout) assessmentLayout.style.display = "none";
  if (glossaryLayout) glossaryLayout.style.display = "none";
  if (quizLayout) quizLayout.style.display = "none";

  // Hide all metrics
  if (learningMetrics) learningMetrics.style.display = "none";
  if (assessmentMetrics) assessmentMetrics.style.display = "none";
  if (glossaryMetrics) glossaryMetrics.style.display = "none";
  if (quizMetrics) quizMetrics.style.display = "none";

  if (newMode === "learning") {
    if (btnLearning) {
      btnLearning.classList.add("active");
      btnLearning.setAttribute("aria-selected", "true");
    }
    if (learningLayout) learningLayout.style.display = "flex";
    if (learningMetrics) learningMetrics.style.display = "flex";

    if (updateHash && typeof currentAttackId !== "undefined") {
      window.location.hash = `${currentAttackId}?tab=${currentTab || 'anatomy'}&filter=${currentFilter || 'all'}`;
    }
  } else if (newMode === "assessment") {
    if (btnAssessment) {
      btnAssessment.classList.add("active");
      btnAssessment.setAttribute("aria-selected", "true");
    }
    if (assessmentLayout) assessmentLayout.style.display = "flex";
    if (assessmentMetrics) assessmentMetrics.style.display = "flex";

    loadScenario(currentScenarioId, false);

    if (updateHash) {
      window.location.hash = `assessment?scenario=${currentScenarioId}`;
    }
  } else if (newMode === "glossary") {
    if (btnGlossary) {
      btnGlossary.classList.add("active");
      btnGlossary.setAttribute("aria-selected", "true");
    }
    if (glossaryLayout) glossaryLayout.style.display = "block";
    if (glossaryMetrics) glossaryMetrics.style.display = "flex";

    if (typeof renderGlossaryList === "function") {
      renderGlossaryList();
    }

    if (updateHash) {
      window.location.hash = "glossary";
    }
  } else if (newMode === "quiz") {
    if (btnQuiz) {
      btnQuiz.classList.add("active");
      btnQuiz.setAttribute("aria-selected", "true");
    }
    if (quizLayout) quizLayout.style.display = "block";
    if (quizMetrics) quizMetrics.style.display = "flex";

    if (typeof renderQuizWorkspace === "function") {
      renderQuizWorkspace();
    }

    if (updateHash) {
      window.location.hash = "quiz";
    }
  }
}

// =============================================================================
// SCENARIO MANAGEMENT
// =============================================================================

function loadScenario(scenarioId, updateHash = true) {
  const scenario = SCENARIOS_DATA.find(s => s.id === scenarioId) || SCENARIOS_DATA[0];
  currentScenarioId = scenario.id;
  activeScenario = scenario;

  if (updateHash) {
    window.location.hash = `assessment?scenario=${scenario.id}`;
  }

  // Update Scenario selector UI active item
  document.querySelectorAll(".sc-card-item").forEach(card => {
    card.classList.toggle("active", card.getAttribute("data-id") === scenario.id);
  });

  // Render Subsections
  renderEnterprisePortfolioSummary();
  renderScenarioDossierHeader(scenario);
  renderFinancialCommandBar(scenario);
  renderAttacksList(scenario);
  renderDefensesList(scenario);
  renderTelemetryLogs(scenario);
  updateTopNavAssessmentMetrics(scenario);
}

function renderScenarioSelector() {
  const container = document.getElementById("scenario-list-container");
  if (!container) return;

  container.innerHTML = "";

  SCENARIOS_DATA.forEach(scenario => {
    const card = document.createElement("div");
    card.className = `sc-card-item ${scenario.id === currentScenarioId ? 'active' : ''}`;
    card.setAttribute("data-id", scenario.id);
    card.setAttribute("tabindex", "0");
    card.setAttribute("role", "button");

    card.innerHTML = `
      <div class="sc-card-header">
        <span class="sc-domain-badge ${scenario.domainTag}">${scenario.domainTag.toUpperCase()}</span>
        <span class="sc-diff-badge ${scenario.difficulty.toLowerCase()}">${scenario.difficulty}</span>
      </div>
      <div class="sc-card-title">${scenario.shortTitle}</div>
      <div class="sc-card-meta">
        <span>Budget: <strong>$${(scenario.budget / 1000).toFixed(0)}k</strong></span>
        <span>Threats: <strong>${scenario.attacks.length}</strong></span>
      </div>
    `;

    card.addEventListener("click", () => {
      loadScenario(scenario.id);
    });

    container.appendChild(card);
  });
}

function renderScenarioDossierHeader(scenario) {
  const headerContainer = document.getElementById("scenario-dossier-header");
  if (!headerContainer) return;

  headerContainer.innerHTML = `
    <div class="sc-header-top">
      <div class="sc-tag-group">
        <span class="sc-domain-badge ${scenario.domainTag}">${scenario.domain.toUpperCase()}</span>
        <span class="sc-diff-badge ${scenario.difficulty.toLowerCase()}">SEVERITY: ${scenario.difficulty.toUpperCase()}</span>
        <span class="sc-actor-badge"><svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> ${scenario.threatActor}</span>
      </div>
      <div class="sc-risk-box">
        <span class="sc-risk-label">Potential Breach Exposure</span>
        <span class="sc-risk-value">$${(scenario.potentialDamage / 1000000).toFixed(1)}M</span>
      </div>
    </div>

    <h2 class="sc-dossier-title">${scenario.title}</h2>
    <p class="sc-dossier-summary">${scenario.summary}</p>

    <div class="sc-meta-row">
      <div class="sc-meta-col">
        <span class="meta-label">Primary Target Infrastructure</span>
        <span class="meta-val">${scenario.targetAsset}</span>
      </div>
      <div class="sc-meta-col">
        <span class="meta-label">Time Window / SLA</span>
        <span class="meta-val" style="color: var(--color-critical);">${scenario.timeWindow}</span>
      </div>
      <div class="sc-meta-col">
        <span class="meta-label">Incident Response Mandate</span>
        <span class="meta-val" style="color: var(--color-safe);">Deploy cost-effective countermeasures within allocated budget</span>
      </div>
    </div>
  `;
}

// =============================================================================
// FINANCIAL & MITIGATION CALCULATIONS
// =============================================================================

function getScenarioState(scenarioId) {
  if (!scenarioAllocations[scenarioId]) {
    scenarioAllocations[scenarioId] = {
      activeDefenses: new Set(),
      logs: []
    };
  }
  return scenarioAllocations[scenarioId];
}

function calculateSpentBudget(scenario) {
  const state = getScenarioState(scenario.id);
  let spent = 0;
  scenario.defenses.forEach(def => {
    if (state.activeDefenses.has(def.id)) {
      spent += def.cost;
    }
  });
  return spent;
}

function calculateAttackMitigations(scenario) {
  const state = getScenarioState(scenario.id);
  const mitigations = {};

  scenario.attacks.forEach(atk => {
    mitigations[atk.id] = 0;
  });

  // Calculate cumulative mitigation contributions
  scenario.defenses.forEach(def => {
    if (state.activeDefenses.has(def.id)) {
      def.mitigations.forEach(mit => {
        if (typeof mitigations[mit.attackId] !== "undefined") {
          mitigations[mit.attackId] = Math.min(100, mitigations[mit.attackId] + mit.percent);
        }
      });
    }
  });

  return mitigations;
}

function calculateOverallMitigation(scenario) {
  const mitigations = calculateAttackMitigations(scenario);
  const attackIds = Object.keys(mitigations);
  if (attackIds.length === 0) return 0;

  const total = attackIds.reduce((sum, id) => sum + mitigations[id], 0);
  return Math.round(total / attackIds.length);
}

function calculateAvertedLoss(scenario) {
  const mitigations = calculateAttackMitigations(scenario);
  let averted = 0;

  scenario.attacks.forEach(atk => {
    const mitPercent = mitigations[atk.id] || 0;
    averted += (atk.damage * (mitPercent / 100));
  });

  return Math.round(averted);
}

// =============================================================================
// OVERALL ENTERPRISE PORTFOLIO CALCULATIONS (All Scenarios)
// =============================================================================

function calculateEnterpriseBudget() {
  let totalBudget = 0;
  let totalSpent = 0;

  SCENARIOS_DATA.forEach(sc => {
    totalBudget += sc.budget;
    totalSpent += calculateSpentBudget(sc);
  });

  const totalRemaining = totalBudget - totalSpent;
  const budgetRatioRemaining = Math.max(0, Math.round((totalRemaining / totalBudget) * 100));

  return { totalBudget, totalSpent, totalRemaining, budgetRatioRemaining };
}

function calculateEnterpriseMitigation() {
  let totalMitigation = 0;
  SCENARIOS_DATA.forEach(sc => {
    totalMitigation += calculateOverallMitigation(sc);
  });
  return Math.round(totalMitigation / SCENARIOS_DATA.length);
}

function calculateEnterpriseAvertedLoss() {
  let totalPotential = 0;
  let totalAverted = 0;

  SCENARIOS_DATA.forEach(sc => {
    totalPotential += sc.potentialDamage;
    totalAverted += calculateAvertedLoss(sc);
  });

  return { totalPotential, totalAverted, totalResidual: totalPotential - totalAverted };
}

function calculateScenarioScore(scenario) {
  const spent = calculateSpentBudget(scenario);
  const remaining = scenario.budget - spent;
  const overallMitigation = calculateOverallMitigation(scenario);
  const state = getScenarioState(scenario.id);

  const budgetRatio = Math.max(0, Math.min(1, remaining / scenario.budget));
  const activeTiers = new Set();
  scenario.defenses.forEach(def => {
    if (state.activeDefenses.has(def.id)) {
      activeTiers.add(def.tier);
    }
  });
  const tierDiversityScore = Math.min(1, activeTiers.size / 3);

  let score = Math.round((overallMitigation * 0.65) + (budgetRatio * 100 * 0.20) + (tierDiversityScore * 100 * 0.15));
  if (remaining < 0) score = Math.max(0, score - 30);

  let grade = "F";
  let gradeClass = "rank-f";
  if (score >= 95) { grade = "S"; gradeClass = "rank-s"; }
  else if (score >= 85) { grade = "A"; gradeClass = "rank-a"; }
  else if (score >= 70) { grade = "B"; gradeClass = "rank-b"; }
  else if (score >= 50) { grade = "C"; gradeClass = "rank-c"; }

  return { score, grade, gradeClass, spent, remaining, overallMitigation };
}

function calculateEnterpriseScore() {
  let totalScore = 0;
  const scenarioScores = [];

  SCENARIOS_DATA.forEach(sc => {
    const scData = calculateScenarioScore(sc);
    scenarioScores.push({ scenario: sc, ...scData });
    totalScore += scData.score;
  });

  const avgScore = Math.round(totalScore / SCENARIOS_DATA.length);

  let grade = "F";
  let gradeClass = "grade-f";
  let statusText = "Critical Enterprise Exposure";

  if (avgScore >= 95) {
    grade = "S";
    gradeClass = "grade-s";
    statusText = "Elite Resilient Enterprise Defense";
  } else if (avgScore >= 85) {
    grade = "A";
    gradeClass = "grade-a";
    statusText = "Hardened Enterprise Defense Posture";
  } else if (avgScore >= 70) {
    grade = "B";
    gradeClass = "grade-b";
    statusText = "Adequate Defense with Residual Exposure";
  } else if (avgScore >= 50) {
    grade = "C";
    gradeClass = "grade-c";
    statusText = "Under-Funded & Vulnerable Enterprise Estate";
  }

  return {
    score: avgScore,
    grade,
    gradeClass,
    statusText,
    scenarioScores
  };
}

function renderEnterprisePortfolioSummary() {
  const container = document.getElementById("enterprise-portfolio-summary");
  if (!container) return;

  const entBudget = calculateEnterpriseBudget();
  const entMitigation = calculateEnterpriseMitigation();
  const entAverted = calculateEnterpriseAvertedLoss();
  const entScore = calculateEnterpriseScore();

  container.innerHTML = `
    <div class="portfolio-header-row">
      <div class="portfolio-title-group">
        <span class="portfolio-badge-pill">GLOBAL DEFENSE COMMAND</span>
        <h3 class="portfolio-heading">ENTERPRISE PORTFOLIO POSTURE (${SCENARIOS_DATA.length} INCIDENT SCENARIOS)</h3>
      </div>
      <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
        <div class="portfolio-score-badge ${entScore.gradeClass}">
          <span>OVERALL GRADE ${entScore.grade}</span>
          <span>â€¢</span>
          <span>${entScore.score} / 100</span>
        </div>
        <button class="portfolio-audit-btn" id="btn-open-portfolio-modal" title="View Detailed Multi-Scenario Audit">
          <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
          </svg>
          <span>All-Scenarios Scorecard</span>
        </button>
      </div>
    </div>

    <div class="portfolio-stats-grid">
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Total Enterprise Budget</span>
        <span class="portfolio-stat-val">$${(entBudget.totalBudget / 1000).toFixed(0)}k</span>
      </div>
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Total Expended Capital</span>
        <span class="portfolio-stat-val spent">-$${(entBudget.totalSpent / 1000).toFixed(0)}k</span>
      </div>
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Deployable Capital</span>
        <span class="portfolio-stat-val ${entBudget.totalRemaining < 200000 ? 'critical' : 'safe'}">$${(entBudget.totalRemaining / 1000).toFixed(0)}k</span>
      </div>
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Enterprise Mitigation</span>
        <span class="portfolio-stat-val highlight">${entMitigation}%</span>
      </div>
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Damages Prevented</span>
        <span class="portfolio-stat-val safe">$${(entAverted.totalAverted / 1000000).toFixed(1)}M</span>
      </div>
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Residual Exposure Risk</span>
        <span class="portfolio-stat-val ${entAverted.totalResidual > 15000000 ? 'critical' : 'safe'}">$${(entAverted.totalResidual / 1000000).toFixed(1)}M</span>
      </div>
    </div>

    <div class="portfolio-dual-tracks">
      <div class="portfolio-track-box">
        <div class="portfolio-track-label">
          <span>Enterprise Capital Liquidity (${entBudget.budgetRatioRemaining}% Available)</span>
          <span>$${entBudget.totalRemaining.toLocaleString()} remaining</span>
        </div>
        <div class="portfolio-track-bar">
          <div class="portfolio-fill-budget" style="width: ${entBudget.budgetRatioRemaining}%;"></div>
        </div>
      </div>
      <div class="portfolio-track-box">
        <div class="portfolio-track-label">
          <span>Global Threat Neutralization (${entMitigation}% Hardened)</span>
          <span>${entMitigation >= 80 ? 'DEFENSE SECURED' : 'ELEVATED RISK'}</span>
        </div>
        <div class="portfolio-track-bar">
          <div class="portfolio-fill-mitigation" style="width: ${entMitigation}%;"></div>
        </div>
      </div>
    </div>
  `;

  const auditBtn = document.getElementById("btn-open-portfolio-modal");
  if (auditBtn) {
    auditBtn.addEventListener("click", openPortfolioScorecardModal);
  }
}

function openPortfolioScorecardModal() {
  const modal = document.getElementById("portfolio-modal");
  const modalBody = document.getElementById("portfolio-modal-body");
  if (!modal || !modalBody) return;

  const entBudget = calculateEnterpriseBudget();
  const entMitigation = calculateEnterpriseMitigation();
  const entAverted = calculateEnterpriseAvertedLoss();
  const entScore = calculateEnterpriseScore();

  modalBody.innerHTML = `
    <div class="scorecard-container">
      <div class="scorecard-badge-row">
        <div class="rank-shield rank-${entScore.grade.toLowerCase()}">
          <span class="rank-letter">${entScore.grade}</span>
          <span class="rank-sub">ENTERPRISE</span>
        </div>
        <div class="scorecard-title-block">
          <span class="scorecard-kicker">EXECUTIVE CISO ENTERPRISE DEFENSE AUDIT</span>
          <h3 class="scorecard-heading">${entScore.statusText}</h3>
          <p class="scorecard-meta">Global Enterprise Score: <strong>${entScore.score} / 100</strong> â€¢ Scenarios Audited: <strong>${SCENARIOS_DATA.length}</strong> â€¢ Budget Status: <strong>$${(entBudget.totalSpent / 1000).toFixed(0)}k spent of $${(entBudget.totalBudget / 1000).toFixed(0)}k</strong></p>
        </div>
      </div>

      <div class="scorecard-stats-grid">
        <div class="score-card-stat">
          <span class="sc-label">Enterprise Mitigation</span>
          <span class="sc-num ${entMitigation >= 80 ? 'good' : 'bad'}">${entMitigation}%</span>
          <span class="sc-sub">Average across 10 Scenarios</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Total Capital Expended</span>
          <span class="sc-num">$${(entBudget.totalSpent / 1000).toFixed(0)}k</span>
          <span class="sc-sub">of $${(entBudget.totalBudget / 1000).toFixed(0)}k Allocated</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Total Damages Averted</span>
          <span class="sc-num good">$${(entAverted.totalAverted / 1000000).toFixed(1)}M</span>
          <span class="sc-sub">of $${(entAverted.totalPotential / 1000000).toFixed(1)}M Total Risk</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Remaining Deployable Funds</span>
          <span class="sc-num ${entBudget.totalRemaining > 0 ? 'good' : 'bad'}">$${(entBudget.totalRemaining / 1000).toFixed(0)}k</span>
          <span class="sc-sub">${entBudget.totalRemaining >= 0 ? 'Solvent Enterprise Budget' : 'Deficit'}</span>
        </div>
      </div>

      <div class="scorecard-debrief">
        <h4>Executive SOC Multi-Incident Evaluation</h4>
        <p>
          Comprehensive enterprise-wide security posture across all 10 high-stakes cyber incident scenarios: Banking Core DDoS, Hospital Ransomware, Cloud Microservices Breach, SCADA Grid Infiltration, Rogue AP Wiretapping, Container Breakout, OWASP Top 10 API Infiltration, Critical Database Blind SQLi, Storage Ransom-Wiper Sabotage, and HTTP Request Smuggling.
        </p>
      </div>

      <div class="portfolio-table-wrap">
        <table class="portfolio-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Scenario</th>
              <th>Domain</th>
              <th>Difficulty</th>
              <th>Budget</th>
              <th>Spent</th>
              <th>Mitigation</th>
              <th>Score</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${entScore.scenarioScores.map((item, idx) => `
              <tr>
                <td><strong>0${idx + 1}</strong></td>
                <td><strong>${item.scenario.shortTitle}</strong></td>
                <td><span class="sc-domain-badge ${item.scenario.domainTag}">${item.scenario.domainTag.toUpperCase()}</span></td>
                <td><span class="sc-diff-badge ${item.scenario.difficulty.toLowerCase()}">${item.scenario.difficulty}</span></td>
                <td>$${(item.scenario.budget / 1000).toFixed(0)}k</td>
                <td style="color: var(--color-high);">-$${(item.spent / 1000).toFixed(0)}k</td>
                <td><span style="font-weight: 700; color: ${item.overallMitigation >= 80 ? 'var(--color-safe)' : (item.overallMitigation >= 40 ? 'var(--color-high)' : 'var(--color-critical)')};">${item.overallMitigation}%</span></td>
                <td><span style="font-weight: 800; color: var(--color-cyan);">${item.score}/100 (${item.grade})</span></td>
                <td>
                  <button class="sc-link-btn" onclick="switchScenarioFromModal('${item.scenario.id}')">Switch</button>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>

      <div class="scorecard-modal-footer" style="margin-top: 20px;">
        <button class="modal-btn close-btn" id="btn-close-portfolio-modal">Close Portfolio Audit</button>
      </div>
    </div>
  `;

  modal.classList.add("show");

  const closeBtn = document.getElementById("btn-close-portfolio-modal");
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      modal.classList.remove("show");
    });
  }
}

function switchScenarioFromModal(scenarioId) {
  const modal = document.getElementById("portfolio-modal");
  if (modal) modal.classList.remove("show");
  loadScenario(scenarioId);
}
window.switchScenarioFromModal = switchScenarioFromModal;
window.openPortfolioScorecardModal = openPortfolioScorecardModal;

// =============================================================================
// RENDER FINANCIAL COMMAND BAR
// =============================================================================

function renderFinancialCommandBar(scenario) {
  const container = document.getElementById("financial-command-bar");
  if (!container) return;

  const spent = calculateSpentBudget(scenario);
  const remaining = scenario.budget - spent;
  const overallMitigation = calculateOverallMitigation(scenario);
  const avertedLoss = calculateAvertedLoss(scenario);
  const budgetPercentRemaining = Math.max(0, Math.round((remaining / scenario.budget) * 100));

  // Determine budget meter color
  let budgetColorClass = "healthy";
  if (budgetPercentRemaining < 20) budgetColorClass = "critical";
  else if (budgetPercentRemaining < 45) budgetColorClass = "warning";

  container.innerHTML = `
    <div class="fin-card">
      <div class="fin-stat-group">
        <div class="fin-stat-box">
          <span class="fin-label">Scenario Defense Budget</span>
          <span class="fin-value" id="fin-total-budget">$${scenario.budget.toLocaleString()}</span>
        </div>
        <div class="fin-stat-box">
          <span class="fin-label">Capital Expended</span>
          <span class="fin-value spent" id="fin-spent-budget">-$${spent.toLocaleString()}</span>
        </div>
        <div class="fin-stat-box">
          <span class="fin-label">Remaining Deployable Funds</span>
          <span class="fin-value ${budgetColorClass}" id="fin-remaining-budget">$${remaining.toLocaleString()}</span>
        </div>
        <div class="fin-stat-box">
          <span class="fin-label">Threats Neutralized</span>
          <span class="fin-value highlight" id="fin-mitigation-val">${overallMitigation}%</span>
        </div>
        <div class="fin-stat-box">
          <span class="fin-label">Estimated Damages Averted</span>
          <span class="fin-value safe" id="fin-averted-loss">$${(avertedLoss / 1000).toFixed(0)}k</span>
        </div>
      </div>

      <!-- Live Budget Gauge Bar -->
      <div class="fin-progress-row">
        <div class="fin-progress-info">
          <span>Budget Liquidity: ${budgetPercentRemaining}% (${remaining >= 0 ? '$' + remaining.toLocaleString() + ' remaining' : 'BUDGET EXCEEDED'})</span>
          <span>Attack Mitigation Index: ${overallMitigation}% Hardened</span>
        </div>
        <div class="fin-track">
          <div class="fin-fill ${budgetColorClass}" style="width: ${Math.min(100, budgetPercentRemaining)}%;"></div>
        </div>
      </div>

      <!-- Action Buttons -->
      <div class="fin-actions-row">
        <div class="fin-actions-left">
          <button class="action-btn sim-btn ${isSimulating ? 'running' : ''}" id="btn-run-simulation" ${isSimulating ? 'disabled' : ''}>
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
              <polygon points="5 3 19 12 5 21 5 3"></polygon>
            </svg>
            <span>${isSimulating ? 'Adversary Simulation In Progress...' : 'Launch Adversary Simulation'}</span>
          </button>
          <button class="action-btn eval-btn" id="btn-eval-scorecard">
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14 2 14 8 20 8"></polyline>
              <line x1="16" y1="13" x2="8" y2="13"></line>
              <line x1="16" y1="17" x2="8" y2="17"></line>
              <polyline points="10 9 9 9 8 9"></polyline>
            </svg>
            <span>Evaluate Defense Assessment</span>
          </button>
        </div>
        <div class="fin-actions-right">
          <button class="action-btn reset-btn" id="btn-reset-allocations" title="Reset all deployed countermeasures">
            <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2">
              <polyline points="1 4 1 10 7 10"></polyline>
              <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"></path>
            </svg>
            <span>Reset Scenario Allocations</span>
          </button>
        </div>
      </div>
    </div>
  `;

  // Bind Buttons
  const simBtn = document.getElementById("btn-run-simulation");
  if (simBtn) simBtn.addEventListener("click", () => startAdversarySimulation(scenario));

  const evalBtn = document.getElementById("btn-eval-scorecard");
  if (evalBtn) evalBtn.addEventListener("click", () => evaluateAssessmentScorecard(scenario));

  const resetBtn = document.getElementById("btn-reset-allocations");
  if (resetBtn) resetBtn.addEventListener("click", () => resetScenarioAllocations(scenario));
}

// =============================================================================
// RENDER ATTACKS LIST
// =============================================================================

function renderAttacksList(scenario) {
  const container = document.getElementById("attacks-column-container");
  if (!container) return;

  const state = getScenarioState(scenario.id);
  const mitigations = calculateAttackMitigations(scenario);

  let html = `
    <div class="panel-section-header">
      <div class="panel-section-title">
        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" fill="none" stroke-width="2">
          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
        </svg>
        <span>Active Adversary Threat Vectors (${scenario.attacks.length})</span>
      </div>
      <span class="panel-section-badge critical">DEFCON ACTIVE</span>
    </div>
    <div class="attacks-list-grid">
  `;

  scenario.attacks.forEach(atk => {
    const mitPercent = mitigations[atk.id] || 0;
    const isNeutralized = mitPercent >= 100;
    const isPartial = mitPercent > 0 && mitPercent < 100;

    let statusTagClass = "unmitigated";
    let statusLabel = "THREAT ACTIVE (CRITICAL)";
    if (isNeutralized) {
      statusTagClass = "neutralized";
      statusLabel = "NEUTRALIZED 100%";
    } else if (isPartial) {
      statusTagClass = "partial";
      statusLabel = `MITIGATED ${mitPercent}%`;
    }

    // Find which deployed defenses are mitigating this attack
    const activeMitigatingDefenses = scenario.defenses.filter(def => {
      return state.activeDefenses.has(def.id) && def.mitigations.some(m => m.attackId === atk.id);
    });

    html += `
      <div class="attack-vector-card ${isNeutralized ? 'neutralized' : (isPartial ? 'partial' : 'active-threat')}">
        <div class="atk-card-top">
          <div class="atk-ident">
            <span class="atk-stage-tag">${atk.stage}</span>
            <span class="atk-mitre-tag">${atk.mitre}</span>
          </div>
          <div class="atk-status-badge ${statusTagClass}">
            ${isNeutralized ? `
              <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" fill="none" stroke-width="3">
                <polyline points="20 6 9 17 4 12"></polyline>
              </svg>
            ` : ''}
            <span>${statusLabel}</span>
          </div>
        </div>

        <h4 class="atk-name">${atk.name}</h4>
        <p class="atk-desc">${atk.desc}</p>

        <div class="atk-telemetry-box">
          <span class="atk-telemetry-label">Telemetry Signatures:</span>
          <span class="atk-telemetry-text">${atk.indicators}</span>
        </div>

        <div class="atk-financial-risk">
          <span>Unmitigated Exposure: <strong>$${(atk.damage / 1000).toFixed(0)}k</strong></span>
          <span>Residual Risk: <strong style="color: ${isNeutralized ? 'var(--color-safe)' : 'var(--color-critical)'};">$${((atk.damage * (1 - mitPercent/100)) / 1000).toFixed(0)}k</strong></span>
        </div>

        <div class="atk-mitigation-progress">
          <div class="atk-progress-track">
            <div class="atk-progress-fill ${isNeutralized ? 'full' : (isPartial ? 'partial' : 'zero')}" style="width: ${mitPercent}%;"></div>
          </div>
        </div>

        <div class="atk-active-countermeasures">
          <span class="active-count-label">Active Mitigations:</span>
          ${activeMitigatingDefenses.length > 0 ? 
            activeMitigatingDefenses.map(d => `<span class="active-def-chip">${d.shortName}</span>`).join("") :
            '<span class="no-def-chip">No countermeasures initiated</span>'
          }
        </div>
      </div>
    `;
  });

  html += `</div>`;
  container.innerHTML = html;
}

// =============================================================================
// RENDER DEFENSES LIST WITH COST TO DEFEND
// =============================================================================

function renderDefensesList(scenario) {
  const container = document.getElementById("defenses-column-container");
  if (!container) return;

  const state = getScenarioState(scenario.id);
  const spent = calculateSpentBudget(scenario);
  const remaining = scenario.budget - spent;

  let html = `
    <div class="panel-section-header">
      <div class="panel-section-title">
        <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" fill="none" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span>Available Defense Countermeasures (${scenario.defenses.length})</span>
      </div>
      <span class="panel-section-badge budget-badge">REMAINING: $${remaining.toLocaleString()}</span>
    </div>
    <div class="defenses-list-grid">
  `;

  scenario.defenses.forEach(def => {
    const isDeployed = state.activeDefenses.has(def.id);
    const canAfford = remaining >= def.cost;

    // Build impact pills
    const impactPillsHtml = def.mitigations.map(m => {
      const targetAtk = scenario.attacks.find(a => a.id === m.attackId);
      const shortName = targetAtk ? targetAtk.shortName : m.attackId;
      return `<span class="def-impact-pill">+${m.percent}% ${shortName}</span>`;
    }).join("");

    let actionButtonHtml = "";
    if (isDeployed) {
      actionButtonHtml = `
        <button class="def-toggle-btn deployed" data-id="${def.id}" title="Click to decommission countermeasure and refund $${def.cost.toLocaleString()} to budget">
          <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="3">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
          <span>Initiated & Active (-$${def.cost.toLocaleString()})</span>
          <span class="revoke-label">[Click to Revoke]</span>
        </button>
      `;
    } else if (canAfford) {
      actionButtonHtml = `
        <button class="def-toggle-btn initiate" data-id="${def.id}">
          <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
          </svg>
          <span>Initiate Defense: $${def.cost.toLocaleString()}</span>
        </button>
      `;
    } else {
      actionButtonHtml = `
        <button class="def-toggle-btn insufficient" data-id="${def.id}" disabled title="Insufficient budget remaining. Revoke other defenses to reallocate capital.">
          <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
          </svg>
          <span>Insufficient Budget (Requires $${def.cost.toLocaleString()})</span>
        </button>
      `;
    }

    html += `
      <div class="defense-countermeasure-card ${isDeployed ? 'deployed' : ''}">
        <div class="def-card-top">
          <div class="def-tier-tag">${def.tier}</div>
          <div class="def-cost-badge">
            <span class="cost-label">COST TO DEFEND:</span>
            <span class="cost-num">$${def.cost.toLocaleString()}</span>
          </div>
        </div>

        <h4 class="def-name">${def.name}</h4>
        <p class="def-desc">${def.desc}</p>

        <div class="def-impact-container">
          <span class="def-impact-label">Mitigation Efficacy:</span>
          <div class="def-impact-pills-row">
            ${impactPillsHtml}
          </div>
        </div>

        <div class="def-btn-container">
          ${actionButtonHtml}
        </div>
      </div>
    `;
  });

  html += `</div>`;
  container.innerHTML = html;

  // Add click listeners to all initiate/revoke buttons
  container.querySelectorAll(".def-toggle-btn:not([disabled])").forEach(btn => {
    btn.addEventListener("click", () => {
      const defId = btn.getAttribute("data-id");
      toggleDefenseCountermeasure(scenario, defId);
    });
  });
}

// =============================================================================
// INITIATE & MITIGATE LOGIC
// =============================================================================

function toggleDefenseCountermeasure(scenario, defenseId) {
  const state = getScenarioState(scenario.id);
  const def = scenario.defenses.find(d => d.id === defenseId);
  if (!def) return;

  const spent = calculateSpentBudget(scenario);
  const remaining = scenario.budget - spent;

  if (state.activeDefenses.has(def.id)) {
    // Revoke Defense
    state.activeDefenses.delete(def.id);
    addTelemetryLog(scenario, "warning", `[COUNTERMEASURE DECOMMISSIONED] ${def.name} revoked. +$${def.cost.toLocaleString()} refunded to defense budget.`);
    showToast(`Countermeasure revoked: +$${def.cost.toLocaleString()} refunded to budget.`);
  } else {
    // Check if can afford
    if (remaining < def.cost) {
      addTelemetryLog(scenario, "critical", `[BUDGET EXHAUSTION] Attempted to initiate "${def.name}" ($${def.cost.toLocaleString()}), but remaining budget is only $${remaining.toLocaleString()}. Action denied.`);
      showToast(`⚠️ Insufficient Budget! You need $${(def.cost - remaining).toLocaleString()} more.`);
      return;
    }

    // Initiate Defense
    state.activeDefenses.add(def.id);
    addTelemetryLog(scenario, "safe", `[DEFENSE INITIATED] ${def.name} deployed (-$${def.cost.toLocaleString()}). Mitigation controls applied to target attack vectors.`);
    showToast(`Defense Initiated: -$${def.cost.toLocaleString()} deducted.`);
  }

  // Check if 100% neutralized
  const overallMitigation = calculateOverallMitigation(scenario);
  if (overallMitigation >= 100) {
    addTelemetryLog(scenario, "safe", `[DEFENSE TARGET ACHIEVED] All active threat vectors are 100% neutralized within budget constraints.`);
  }

  // Refresh Views
  renderEnterprisePortfolioSummary();
  renderFinancialCommandBar(scenario);
  renderAttacksList(scenario);
  renderDefensesList(scenario);
  renderTelemetryLogs(scenario);
  updateTopNavAssessmentMetrics(scenario);
}

function resetScenarioAllocations(scenario) {
  const state = getScenarioState(scenario.id);
  state.activeDefenses.clear();
  addTelemetryLog(scenario, "info", `[SCENARIO RESET] All initiated defense methods revoked. Full budget of $${scenario.budget.toLocaleString()} restored.`);
  showToast("Scenario allocations reset to default.");

  renderEnterprisePortfolioSummary();
  renderFinancialCommandBar(scenario);
  renderAttacksList(scenario);
  renderDefensesList(scenario);
  renderTelemetryLogs(scenario);
  updateTopNavAssessmentMetrics(scenario);
}

// =============================================================================
// ADVERSARY ATTACK SIMULATION ENGINE
// =============================================================================

function startAdversarySimulation(scenario) {
  if (isSimulating) return;

  isSimulating = true;
  simulationStage = 1;
  const state = getScenarioState(scenario.id);
  const mitigations = calculateAttackMitigations(scenario);

  // Update UI to running state
  renderFinancialCommandBar(scenario);
  addTelemetryLog(scenario, "critical", `>>> [SIMULATION INITIATED] Threat Actor "${scenario.threatActor}" executing coordinated 4-stage kill chain...`);

  // Open / Scroll to simulation radar panel if available
  const radarPanel = document.getElementById("simulation-radar-hud");
  if (radarPanel) {
    radarPanel.style.display = "block";
    radarPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  const stages = [
    {
      num: 1,
      title: "STAGE 1: ADVERSARY RECON & PERIMETER PROBING",
      detail: "Mass port scanning, BGP route flapping, and automated vulnerability fuzzing launched against target assets."
    },
    {
      num: 2,
      title: "STAGE 2: INGRESS WEAPONIZATION & EXPLOIT DELIVERY",
      detail: "Exploitation vectors triggered. Packet floods, credential stuffing, and injection payloads hit perimeter services."
    },
    {
      num: 3,
      title: "STAGE 3: PRIVILEGE ESCALATION & LATERAL MOVEMENT",
      detail: "Adversaries attempt credential harvesting, Active Directory pivoting, and container namespace escapes."
    },
    {
      num: 4,
      title: "STAGE 4: OBJECTIVE IMPACT & DATA EXFILTRATION",
      detail: "Final assault: Ransomware encryption routines, S3 bucket syncing, Modbus coil commands, and BGP route redirection."
    }
  ];

  let currentStageIdx = 0;

  simulationInterval = setInterval(() => {
    if (currentStageIdx < stages.length) {
      const stage = stages[currentStageIdx];
      updateSimulationHUD(scenario, stage.num, stage.title, stage.detail);

      // Check attack vectors corresponding to this stage or overall
      scenario.attacks.forEach(atk => {
        const mit = mitigations[atk.id] || 0;
        if (mit >= 85) {
          addTelemetryLog(scenario, "safe", `  [STAGE ${stage.num} - DEFENSE HOLDING] Attack "${atk.shortName}" BLOCKED by initiated countermeasures (${mit}% efficacy). Zero breach impact.`);
        } else if (mit >= 40) {
          addTelemetryLog(scenario, "warning", `  [STAGE ${stage.num} - DEGRADED DEFENSE] Attack "${atk.shortName}" partially mitigated (${mit}%). Minor telemetry leakage.`);
        } else {
          addTelemetryLog(scenario, "critical", `  [STAGE ${stage.num} - DEFENSE BREACHED] Attack "${atk.shortName}" penetrated defenses! Unmitigated impact incurred: $${((atk.damage * (1 - mit/100)) / 1000).toFixed(0)}k.`);
        }
      });

      renderTelemetryLogs(scenario);
      currentStageIdx++;
    } else {
      // Simulation Finished
      clearInterval(simulationInterval);
      isSimulating = false;
      renderFinancialCommandBar(scenario);

      const overall = calculateOverallMitigation(scenario);
      addTelemetryLog(scenario, overall >= 80 ? "safe" : "critical", `<<< [SIMULATION COMPLETED] Incident simulation resolved with ${overall}% threat mitigation rate.`);
      renderTelemetryLogs(scenario);

      // Auto trigger scorecard modal
      setTimeout(() => {
        evaluateAssessmentScorecard(scenario);
      }, 900);
    }
  }, 1400);
}

function updateSimulationHUD(scenario, stageNum, stageTitle, stageDetail) {
  const hudStageTitle = document.getElementById("sim-hud-stage-title");
  const hudStageDetail = document.getElementById("sim-hud-stage-detail");
  const hudProgressBar = document.getElementById("sim-hud-progress-fill");

  if (hudStageTitle) hudStageTitle.textContent = `${stageTitle}`;
  if (hudStageDetail) hudStageDetail.textContent = stageDetail;
  if (hudProgressBar) hudProgressBar.style.width = `${stageNum * 25}%`;
}

// =============================================================================
// ASSESSMENT EVALUATION & SCORECARD MODAL
// =============================================================================

function evaluateAssessmentScorecard(scenario) {
  const spent = calculateSpentBudget(scenario);
  const remaining = scenario.budget - spent;
  const overallMitigation = calculateOverallMitigation(scenario);
  const avertedLoss = calculateAvertedLoss(scenario);
  const potentialLoss = scenario.potentialDamage;
  const residualLoss = potentialLoss - avertedLoss;
  const state = getScenarioState(scenario.id);

  // Compute Grade & Score
  // Score formula: 65% mitigation weight + 20% budget efficiency + 15% tier diversity
  const budgetRatio = Math.max(0, Math.min(1, remaining / scenario.budget));
  const activeTiers = new Set();
  scenario.defenses.forEach(def => {
    if (state.activeDefenses.has(def.id)) {
      activeTiers.add(def.tier);
    }
  });
  const tierDiversityScore = Math.min(1, activeTiers.size / 3);

  let totalScore = Math.round((overallMitigation * 0.65) + (budgetRatio * 100 * 0.20) + (tierDiversityScore * 100 * 0.15));
  if (remaining < 0) totalScore = Math.max(0, totalScore - 30); // Penalty for overspending

  let rankGrade = "F";
  let rankTitle = "Catastrophic Breach";
  let rankClass = "rank-f";
  let debriefSummary = "Critical security flaws unaddressed. Adversary achieved primary objectives, causing massive enterprise loss.";

  if (totalScore >= 95) {
    rankGrade = "S";
    rankTitle = "Master Cyber Architect";
    rankClass = "rank-s";
    debriefSummary = "Flawless incident defense execution! All attack vectors neutralized within budget constraints with optimal cost-effectiveness and strategic Defense-in-Depth.";
  } else if (totalScore >= 85) {
    rankGrade = "A";
    rankTitle = "Senior SOC Defender";
    rankClass = "rank-a";
    debriefSummary = "High-tier incident mitigation. The enterprise avoided significant financial loss and critical assets remained operational.";
  } else if (totalScore >= 70) {
    rankGrade = "B";
    rankTitle = "Competent Security Engineer";
    rankClass = "rank-b";
    debriefSummary = "Core attack vectors mitigated, but residual exposure remains. Consider rebalancing budget into perimeter-level countermeasures.";
  } else if (totalScore >= 50) {
    rankGrade = "C";
    rankTitle = "Budget Constrained / Vulnerable";
    rankClass = "rank-c";
    debriefSummary = "Multiple critical attacks succeeded in penetrating enterprise defenses. Countermeasures were underfunded or suboptimal.";
  }

  // Render Assessment Modal
  const modal = document.getElementById("assessment-modal");
  const modalContent = document.getElementById("assessment-modal-body");
  if (!modal || !modalContent) return;

  modalContent.innerHTML = `
    <div class="scorecard-container">
      <div class="scorecard-badge-row">
        <div class="rank-shield ${rankClass}">
          <span class="rank-letter">${rankGrade}</span>
          <span class="rank-sub">GRADE</span>
        </div>
        <div class="scorecard-title-block">
          <span class="scorecard-kicker">INCIDENT DEFENSE AUDIT REPORT</span>
          <h3 class="scorecard-heading">${rankTitle}</h3>
          <p class="scorecard-meta">Scenario: <strong>${scenario.title}</strong> • Score: <strong>${totalScore} / 100</strong></p>
        </div>
      </div>

      <div class="scorecard-stats-grid">
        <div class="score-card-stat">
          <span class="sc-label">Threat Mitigation Rate</span>
          <span class="sc-num ${overallMitigation >= 80 ? 'good' : 'bad'}">${overallMitigation}%</span>
          <span class="sc-sub">${overallMitigation >= 100 ? 'All Vectors Neutralized' : 'Residual Threat Remaining'}</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Defense Capital Spent</span>
          <span class="sc-num">$${spent.toLocaleString()}</span>
          <span class="sc-sub">of $${scenario.budget.toLocaleString()} Allocated</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Damages Prevented</span>
          <span class="sc-num good">$${(avertedLoss / 1000).toFixed(0)}k</span>
          <span class="sc-sub">of $${(potentialLoss / 1000).toFixed(0)}k Total Risk</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Residual Exposure</span>
          <span class="sc-num ${residualLoss > 0 ? 'bad' : 'good'}">$${(residualLoss / 1000).toFixed(0)}k</span>
          <span class="sc-sub">${residualLoss === 0 ? 'Zero Financial Loss' : 'Incurred Enterprise Loss'}</span>
        </div>
      </div>

      <div class="scorecard-debrief">
        <h4>Executive SOC Debrief</h4>
        <p>${debriefSummary}</p>
      </div>

      <div class="scorecard-vector-breakdown">
        <h4>Vector-by-Vector Defense Breakdown</h4>
        <div class="vector-audit-list">
          ${scenario.attacks.map(atk => {
            const mit = calculateAttackMitigations(scenario)[atk.id] || 0;
            return `
              <div class="vector-audit-row">
                <div class="vector-audit-info">
                  <span class="vector-audit-name">${atk.shortName}</span>
                  <span class="vector-audit-mitre">${atk.mitre}</span>
                </div>
                <div class="vector-audit-bar-wrap">
                  <div class="vector-audit-bar ${mit >= 100 ? 'full' : (mit > 0 ? 'partial' : 'none')}" style="width: ${mit}%;"></div>
                </div>
                <span class="vector-audit-percent ${mit >= 100 ? 'good' : (mit > 0 ? 'warning' : 'bad')}">${mit}%</span>
              </div>
            `;
          }).join("")}
        </div>
      </div>

      <div class="scorecard-modal-footer">
        <button class="modal-btn close-btn" id="btn-close-modal">Back to Scenario</button>
        <button class="modal-btn next-btn" id="btn-modal-next-scenario">Next Incident Scenario &rarr;</button>
      </div>
    </div>
  `;

  modal.classList.add("show");

  document.getElementById("btn-close-modal").addEventListener("click", () => {
    modal.classList.remove("show");
  });

  const nextBtn = document.getElementById("btn-modal-next-scenario");
  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      modal.classList.remove("show");
      const currentIdx = SCENARIOS_DATA.findIndex(s => s.id === scenario.id);
      const nextIdx = (currentIdx + 1) % SCENARIOS_DATA.length;
      loadScenario(SCENARIOS_DATA[nextIdx].id);
    });
  }
}

// =============================================================================
// TELEMETRY & AUDIT LOGGER
// =============================================================================

function addTelemetryLog(scenario, type, text) {
  const state = getScenarioState(scenario.id);
  state.logs.unshift({
    time: getFormattedTimestamp(),
    type: type,
    text: text
  });

  // Keep max 50 log items
  if (state.logs.length > 50) {
    state.logs.pop();
  }
}

function renderTelemetryLogs(scenario) {
  const container = document.getElementById("telemetry-log-stream");
  if (!container) return;

  const state = getScenarioState(scenario.id);
  container.innerHTML = state.logs.map(log => {
    return `
      <div class="log-entry log-${log.type}">
        <span class="log-time">[${log.time}]</span>
        <span class="log-msg">${escapeHtml(log.text)}</span>
      </div>
    `;
  }).join("");
}

function getFormattedTimestamp() {
  const now = new Date();
  const hrs = String(now.getHours()).padStart(2, '0');
  const min = String(now.getMinutes()).padStart(2, '0');
  const sec = String(now.getSeconds()).padStart(2, '0');
  return `${hrs}:${min}:${sec}`;
}

function updateTopNavAssessmentMetrics(scenario) {
  const remainingEl = document.getElementById("nav-assessment-remaining-budget");
  const mitigationEl = document.getElementById("nav-assessment-mitigation");
  const portfolioScorePill = document.getElementById("nav-portfolio-score-pill");

  if (remainingEl) {
    const spent = calculateSpentBudget(scenario);
    const rem = scenario.budget - spent;
    remainingEl.textContent = `$${rem.toLocaleString()}`;
    remainingEl.className = `metric-val ${rem < 20000 ? 'critical' : 'highlight'}`;
  }

  if (mitigationEl) {
    const overall = calculateOverallMitigation(scenario);
    mitigationEl.textContent = `${overall}%`;
  }

  if (portfolioScorePill) {
    const entScore = calculateEnterpriseScore();
    portfolioScorePill.textContent = `${entScore.score}/100 (${entScore.grade})`;
  }

  const navPortfolioBtn = document.getElementById("btn-nav-portfolio-scorecard");
  if (navPortfolioBtn && !navPortfolioBtn.hasAttribute("data-bound")) {
    navPortfolioBtn.setAttribute("data-bound", "true");
    navPortfolioBtn.addEventListener("click", openPortfolioScorecardModal);
  }
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

// Global Exports
window.switchAppMode = switchAppMode;
window.loadScenario = loadScenario;

