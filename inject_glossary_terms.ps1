# PowerShell script to inject 27 new attack & defense glossary terms into glossary.js
$glossaryPath = 'C:/Users/SubbulakshmiT/.gemini/antigravity-ide/scratch/cyber-attack-book/glossary.js'
$content = [System.IO.File]::ReadAllText($glossaryPath)

$newTerms = @'
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
    definition: "A wide class of flaws where untrusted user input is concatenated directly into interpreter interpreters (SQL, NoSQL, OS Command, LDAP) without contextual escaping or query parameterization.",
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
'@

$lastTermMarker = "    appLinks: { mode: \"assessment\", scenarioId: \"sc_cloud_breach\" }`r`n  }`r`n];"
if (-not $content.Contains($lastTermMarker)) {
    $lastTermMarker = "    appLinks: { mode: \"assessment\", scenarioId: \"sc_cloud_breach\" }`n  }`n];"
}

$markerIdx = $content.IndexOf($lastTermMarker)
if ($markerIdx -lt 0) {
    Write-Host "ERROR: Last term marker not found in glossary.js!"
    exit 1
}

$replacement = "    appLinks: { mode: \"assessment\", scenarioId: \"sc_cloud_breach\" }`r`n  },`r`n" + $newTerms + "`r`n];"

$before = $content.Substring(0, $markerIdx)
$after = $content.Substring($markerIdx + $lastTermMarker.Length)

$newContent = $before + $replacement + $after

# Also update initGlossary to dynamically set glossary-term-badge
$initMarker = "function initGlossary() {"
$initIdx = $newContent.IndexOf($initMarker)
if ($initIdx -ge 0) {
    $initOld = "function initGlossary() {`r`n  renderAlphabetBar();"
    if (-not $newContent.Contains($initOld)) {
        $initOld = "function initGlossary() {`n  renderAlphabetBar();"
    }
    $initNew = "function initGlossary() {`r`n  const badgeEl = document.getElementById('glossary-term-badge');`r`n  if (badgeEl) badgeEl.textContent = `${GLOSSARY_DATA.length} Terms`;`r`n  renderAlphabetBar();"
    $newContent = $newContent.Replace($initOld, $initNew)
}

[System.IO.File]::WriteAllText($glossaryPath, $newContent, [System.Text.Encoding]::UTF8)
Write-Host "SUCCESS: Injected 27 new glossary terms into glossary.js! New length: $($newContent.Length)"
