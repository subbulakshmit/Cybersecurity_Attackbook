# PowerShell script to update assessment.js with 4 new scenarios and enterprise portfolio calculations
$assessmentJsPath = 'C:/Users/SubbulakshmiT/.gemini/antigravity-ide/scratch/cyber-attack-book/assessment.js'
$content = [System.IO.File]::ReadAllText($assessmentJsPath)

$newScenarios = @'
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
'@

# Find where SCENARIOS_DATA ends
$searchMarker = "// =============================================================================`r`n// ASSESSMENT ENGINE STATE MANAGEMENT"
if (-not $content.Contains($searchMarker)) {
    $searchMarker = "// =============================================================================`n// ASSESSMENT ENGINE STATE MANAGEMENT"
}

$markerIdx = $content.IndexOf($searchMarker)
if ($markerIdx -lt 0) {
    Write-Host "ERROR: State management marker not found!"
    exit 1
}

$bracketIdx = $content.LastIndexOf("];", $markerIdx)
if ($bracketIdx -lt 0) {
    Write-Host "ERROR: Bracket not found!"
    exit 1
}

$before = $content.Substring(0, $bracketIdx).TrimEnd()
$after = $content.Substring($bracketIdx)

$newContent = $before + ",`r`n" + $newScenarios + "`r`n" + $after

[System.IO.File]::WriteAllText($assessmentJsPath, $newContent, [System.Text.Encoding]::UTF8)
Write-Host "SUCCESS: Injected 4 new scenarios into assessment.js! New length: $($newContent.Length)"
