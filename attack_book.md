# 🛡️ THE CYBER DEFENDER'S ATTACK BOOK: TOP 5 THREATS
### Comprehensive Attack Dossiers, Detection Engineering, and Defensive Countermeasures

---

## 📋 Table of Contents
1. [Attack #1: Ransomware & Multi-Stage Extortion](#attack-1-ransomware--multi-stage-extortion)
2. [Attack #2: Phishing & Adversary-in-the-Middle (AiTM) MFA Bypass](#attack-2-phishing--adversary-in-the-middle-aitm-mfa-bypass)
3. [Attack #3: SQL Injection (SQLi) & Database Exfiltration](#attack-3-sql-injection-sqli--database-exfiltration)
4. [Attack #4: Server-Side Request Forgery (SSRF) & Cloud Metadata Theft](#attack-4-server-side-request-forgery-ssrf--cloud-metadata-theft)
5. [Attack #5: Distributed Denial of Service (DDoS) & L7 Application Exhaustion](#attack-5-distributed-denial-of-service-ddos--l7-application-exhaustion)
6. [Universal Defense Architecture & Quick-Reference Matrix](#universal-defense-architecture--quick-reference-matrix)

---

# Attack #1: Ransomware & Multi-Stage Extortion

## 1. Executive Summary & Classification
* **Severity**: 🟥 **CRITICAL**
* **Typical Impact Score**: CVSS v3.1: 9.8 / 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
* **Primary Threat Actors**: LockBit 3.0, BlackCat/ALPHV, Cl0p, Akira, RansomHub
* **Target Environment**: Windows Active Directory domains, ESXi Virtualization clusters, NAS/SAN storage arrays, Cloud backups

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | `T1566`, `T1190` | Phishing, Exploit Public-Facing Application (e.g. Citrix, VPNs) |
| **Execution** | `T1059.001` | PowerShell & Living-off-the-Land Binaries (LOLBAS) |
| **Defense Evasion** | `T1562.001`, `T1070` | Impair Defenses (Disable Defender/EDR), Clear Windows Event Logs |
| **Credential Access** | `T1003.001` | OS Credential Dumping: LSASS Memory (Mimikatz) |
| **Lateral Movement** | `T1021.002`, `T1570` | SMB/Windows Admin Shares, Lateral Tool Transfer (PsExec, WMI) |
| **Exfiltration** | `T1567.002` | Exfiltration to Cloud Storage (Rclone, MEGA, MegaSync) |
| **Impact** | `T1486`, `T1490` | Data Encrypted for Impact, Inhibit System Recovery (Delete Shadow Copies) |

---

## 2. Technical Attack Anatomy & Kill Chain Mechanics

Modern enterprise ransomware is **not** an automated single-click worm; it is a **Human-Operated Ransomware (HoR)** campaign spanning hours to weeks:

```
[Initial Access]        Broker buys access / Phishing / VPN 0-Day (e.g., CVE-2023-46805)
       │
       ▼
[Discovery & Esc.]     AdFind, BloodHound, Netscan, Mimikatz (Dump LSASS for DA tokens)
       │
       ▼
[Defense Disablement]  BYOVD (Bring Your Own Vulnerable Driver) to unhook EDR ring-0 kernel
       │
       ▼
[Exfiltration]         Staging sensitive directories -> Rclone to Mega.nz (Double Extortion)
       │
       ▼
[Inhibit Recovery]     vssadmin delete shadows /all /quiet, bcdedit /set {default} recoveryenabled No
       │
       ▼
[Mass Encryption]      GPO / PsExec push payload -> ChaCha20/AES-256 + RSA-4096 public key
```

### Key Technical Mechanisms:
1. **Inhibiting System Recovery**: Threat actors invoke Windows native binaries to destroy recovery mechanisms before encrypting:
   - `vssadmin.exe delete shadows /all /quiet`
   - `wmic.exe shadowcopy delete`
   - `wbadmin.exe delete catalog -quiet`
   - `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures` & `bcdedit.exe /set {default} recoveryenabled no`
2. **Double/Triple Extortion**: Attackers exfiltrate intellectual property and PII before encryption. Even if victims restore from backups, attackers threaten public leak or regulatory reporting (GDPR/SEC).
3. **Bring Your Own Vulnerable Driver (BYOVD)**: Attackers drop legitimate signed drivers (e.g., Process Hacker `kprocesshacker.sys` or vulnerable anti-cheat drivers) to terminate EDR processes in Ring 0.

---

## 3. Telemetry & Detection Methods

### Required Log Sources
* **Windows Event Logs**: Security (Event IDs `4688`, `4672`, `4720`, `1102`), System (`7045` - Service installed)
* **Sysmon**: Event ID `1` (Process Creation), `7` (Image Loaded), `10` (ProcessAccess to `lsass.exe`), `11` (FileCreate with known extensions), `13` (Registry modification)
* **Network Flow & Egress**: Zeek / NetFlow tracking high-volume outbound bursts to Mega, MegaSync, Dropbox, and decentralized storage (IPFS).

### Concrete Detection Signatures

#### A. Sigma Rule: Deletion of Volume Shadow Copies (LOLBAS)
```yaml
title: Volume Shadow Copy Deletion via LOLBAS
id: 5698b7f8-b3d9-4820-b467-33a7d4c89df2
status: production
description: Detects command-line activity commonly used by ransomware to wipe VSS backups and inhibit recovery.
references:
    - https://attack.mitre.org/techniques/T1490/
author: Cyber Threat Intelligence Team
date: 2026/01/15
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
    selection_bcdedit:
        Image|endswith: '\bcdedit.exe'
        CommandLine|contains|all:
            - 'recoveryenabled'
            - 'no'
    selection_wbadmin:
        Image|endswith: '\wbadmin.exe'
        CommandLine|contains|all:
            - 'delete'
            - 'catalog'
    condition: 1 of selection_*
fields:
    - CommandLine
    - ParentImage
    - User
falsepositives:
    - Rare legacy backup scripts (must be verified and allowlisted by hash)
level: critical
tags:
    - attack.impact
    - attack.t1490
```

#### B. Splunk SPL Query: High-Velocity File Renaming / Mass Encryption
```spl
index=sysmon EventCode=11 
| bin _time span=1m 
| stats count dc(TargetFilename) as UniqueFiles by _time, Image, ProcessId, Computer 
| where UniqueFiles > 100 
| regex TargetFilename="\.(locked|enc|crypt|lockbit|blackcat|crypted|akira)$" 
| eval Alert="Potential Ransomware Mass Encryption Active"
| table _time, Computer, Image, ProcessId, UniqueFiles, Alert
```

#### C. Suricata IDS Signature: Rclone / Mega Exfiltration Pattern
```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"SEC-ALERT Ransomware Staging - Rclone WebDAV/REST Exfiltration User-Agent";
    flow:to_server,established;
    content:"User-Agent|3a 20|rclone/"; nocase;
    classtype:policy-violation;
    sid:2026001;
    rev:1;
)
```

---

## 4. Multi-Layered Defense & Mitigation Methods

### Preventative Controls (Zero Trust Architecture)
1. **Air-Gapped / Immutable Backups (3-2-1-1-0 Rule)**:
   - 3 copies of data, on 2 different media types, 1 offsite, 1 **immutable / write-once-read-many (WORM) air-gapped** from the domain, 0 validation errors.
   - Backup management console isolated behind dedicated out-of-band MFA network.
2. **Endpoint Hardening & AppLocker / WDAC**:
   - Implement Windows Defender Application Control (WDAC) enforcing block rules for unsigned binaries in `C:\Users\*` and `C:\ProgramData\*`.
   - Block execution of `vssadmin.exe` and `wbadmin.exe` for standard users via Software Restriction Policies.
3. **Credential Tiering (Active Directory Red Forest / ESAE)**:
   - Domain Admins must never authenticate on tier-1 (servers) or tier-2 (workstations) machines.
   - Enable Windows Defender Credential Guard to prevent LSASS memory extraction.
4. **Network Micro-segmentation**:
   - Enforce Host-Based Firewalls blocking Workstation-to-Workstation SMB (`Port 445`) and RPC (`Port 135`).

### First 60 Minutes Incident Response Protocol
1. **Network Containment**:
   - Issue automated EDR network isolation command to impacted host(s).
   - If lateral spread is suspected across the domain, sever the enterprise internet gateway and quarantine the affected subnet at core switch level.
2. **Preserve Forensic Evidence**:
   - Dump volatile RAM before powering down machines (do NOT reboot; key material may reside in memory).
3. **Revoke & Reset**:
   - Force reset `krbtgt` account password twice to invalidate all existing Kerberos Golden/Silver tickets.
   - Invalidate all active VPN and cloud session tokens.

### Purple Team Emulation (Safe Validation)
```powershell
# Safe Purple Team Test: Validate if EDR/SIEM alerts on shadow copy query
vssadmin.exe list shadows
```

---

# Attack #2: Phishing & Adversary-in-the-Middle (AiTM) MFA Bypass

## 1. Executive Summary & Classification
* **Severity**: 🟥 **CRITICAL**
* **Typical Impact Score**: CVSS v3.1: 9.3 / 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`)
* **Primary Threat Actors**: Storm-0832, Midnight Blizzard, Scattered Spider, FIN7
* **Target Environment**: Microsoft 365 / Entra ID, Google Workspace, Okta, Cloud Single Sign-On (SSO)

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | `T1566.002` | Spearphishing Link |
| **Credential Access** | `T1539` | Steal Web Session Cookie |
| **Credential Access** | `T1621` | Multi-Factor Authentication Request Generation (MFA Fatigue) |
| **Defense Evasion** | `T1556` | Modify Authentication Process |
| **Persistence** | `T1098.005` | Device Registration (Register Rogue MFA Device/FIDO Key) |
| **Collection** | `T1114.002` | Remote Email Collection (Exchange Online Search & Forwarding) |

---

## 2. Technical Attack Anatomy & Kill Chain Mechanics

Traditional phishing steals static passwords, which fails against Multi-Factor Authentication (MFA). **AiTM (Adversary-in-the-Middle)** attacks deploy reverse proxies (e.g., **Evilginx3**, **Muraena**, **Modlishka**) positioned between the victim and legitimate Identity Providers (IdPs):

```
Victim Browser ───(1. Clicks Fake Link)───► Reverse Proxy (Evilginx Server)
                                                    │
                                                    ├──(2. Forwards Request)──► Real IdP (Entra ID/Okta)
                                                    │                             │
                                                    ◄──(3. Relays Real MFA Challenge)
Victim approves MFA Prompt (Push/SMS/TOTP) ─────────► Proxy Intercepts
                                                    │
                                                    ├──(4. Captures Session Token / Cookie `ESTSAUTH`)
                                                    │
                                                    └──► Attacker Clones Session Cookie into Own Browser!
```

### Key Technical Mechanisms:
1. **Reverse Proxy Session Interception**: The proxy fetches real login pages, injects subtle JavaScript hooks, and relays credentials and MFA tokens in real-time.
2. **Session Cookie Theft**: Once authentication succeeds, the IdP sends HTTP response cookies (`ESTSAUTH`, `ESTSAUTHPERSISTENT`, `SESSION_ID`). The proxy intercepts and decrypts these cookies, completely bypassing password + MFA checks.
3. **Post-Bypass Persistence**:
   - Attacker injects session token into their browser, accessing Microsoft 365 with zero authentication prompts.
   - Registers a new Authenticator app or FIDO2 key (`T1098.005`) in the victim's account settings.
   - Configures malicious inbox forwarding rules to hide alert notifications from the victim.

---

## 3. Telemetry & Detection Methods

### Required Log Sources
* **Entra ID / Okta Sign-in Logs**: Authentication method details, IP address, Client App, User Agent, Conditional Access status.
* **Microsoft 365 Unified Audit Log (UAL)**: MailItemsAccessed, New-InboxRule, Add-DistributionGroupMember.
* **DNS & Web Proxy Logs**: Queries for newly registered domains (NRDs), domain age < 30 days, dynamic DNS providers.

### Concrete Detection Signatures

#### A. KQL (Microsoft Sentinel / Defender for Cloud Apps): Impossible Travel & Token Replay
```kql
let ThresholdDistanceKm = 1000;
let TimeWindow = 30m;
SigninLogs
| where ResultType == 0 // Successful sign-in
| project SigninTime = TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, DeviceDetail
| extend City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)
| join kind=inner (
    SigninLogs
    | where ResultType == 0
    | project NextSigninTime = TimeGenerated, UserPrincipalName, NextIP = IPAddress, NextLocation = Location, NextApp = AppDisplayName
) on UserPrincipalName
| where NextSigninTime > SigninTime and NextSigninTime - SigninTime <= TimeWindow
| where IPAddress != NextIP
| project UserPrincipalName, SigninTime, NextSigninTime, IPAddress, NextIP, Location, NextLocation
```

#### B. Splunk SPL: Malicious Mailbox Forwarding Rule Creation (Post-AiTM Persistence)
```spl
index=o365 Workload=Exchange Operation IN ("New-InboxRule", "Set-InboxRule")
| spath input=Parameters output=ForwardTo path=ForwardTo
| spath input=Parameters output=ForwardAsAttachmentTo path=ForwardAsAttachmentTo
| spath input=Parameters output=DeleteMessage path=DeleteMessage
| where isnotnull(ForwardTo) OR isnotnull(ForwardAsAttachmentTo)
| eval SuspiciousAction=if(DeleteMessage=="true", "Forward_And_Delete", "External_Forward")
| table _time, UserId, ClientIP, Operation, ForwardTo, SuspiciousAction
```

#### C. Suricata IDS: Detecting Reverse-Proxy Domain Impersonation
```suricata
alert dns $HOME_NET any -> any 53 (
    msg:"SEC-ALERT AiTM Phishing - Query to Typo-Squatted Corporate Login Domain";
    dns.query; content:"login.microsoftonline.com."; negate;
    dns.query; content:"microsoftonline"; nocase;
    classtype:bad-unknown;
    sid:2026002;
    rev:1;
)
```

---

## 4. Multi-Layered Defense & Mitigation Methods

### Preventative Controls (Phishing-Resistant MFA)
1. **Enforce FIDO2 / WebAuthn Hardware Security Keys**:
   - Standard push/SMS/TOTP codes are vulnerable to AiTM because users can type them into fake sites.
   - **FIDO2 / Passkeys / WebAuthn cryptographic keys (e.g., YubiKey)** bind authentication to the cryptographic origin (`domain name` in TLS). The browser refuses to sign challenges if the URL does not strictly match the registered domain.
2. **Conditional Access with Device Compliance (Intune / Jamf)**:
   - Require that logins succeed **only** from hybrid Azure AD-joined or compliant managed devices equipped with client-side enterprise certificates.
3. **Continuous Access Evaluation (CAE)**:
   - Enforce real-time revocation of access tokens if the user's IP changes suddenly or user risk score escalates.
4. **Email Authentication Strict Enforcement**:
   - Reject unauthenticated emails via strict `DMARC (p=reject)`, `DKIM`, and `SPF` policies.

### Containment Runbook
1. Revoke all active session tokens immediately via `Revoke-AzureADUserAllRefreshToken`.
2. Delete any newly created mailbox forwarding rules or delegated OAuth applications.
3. Inspect and remove any unauthorized MFA registration devices added within the last 24 hours.

---

# Attack #3: SQL Injection (SQLi) & Database Exfiltration

## 1. Executive Summary & Classification
* **Severity**: 🟥 **CRITICAL**
* **Typical Impact Score**: CVSS v3.1: 9.8 / 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
* **Primary Threat Vectors**: OWASP Top 10 - A03:2021 (Injection), CWE-89
* **Target Environment**: Web Applications, APIs (REST/GraphQL), Microservices, SQL Databases (PostgreSQL, MySQL, MSSQL, Oracle)

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | `T1190` | Exploit Public-Facing Application |
| **Execution** | `T1059` | Command and Scripting Interpreter (e.g., `xp_cmdshell`) |
| **Collection** | `T1005` | Data from Local System / Database Schema Discovery |
| **Exfiltration** | `T1048` | Exfiltration Over Alternative Protocol (DNS/OOB) |

---

## 2. Technical Attack Anatomy & Kill Chain Mechanics

SQL Injection occurs when untrusted user input is directly concatenated into dynamic SQL queries without parameterized binding:

```
[Attacker HTTP Request] ──► GET /api/users?id=1' UNION SELECT null, username, password_hash FROM admin_users--
                                    │
                                    ▼
[Vulnerable Web Server] ──► SELECT * FROM accounts WHERE id = '1' UNION SELECT null, username, password_hash FROM admin_users--'
                                    │
                                    ▼
[Database Engine]       ──► Executes Combined Query & Returns Entire Admin Table in JSON Response!
```

### Attack Variants:
1. **In-Band / UNION-Based SQLi**: Direct extraction where output is reflected in the HTTP response.
2. **Error-Based SQLi**: Triggering intentional database errors (e.g., `CAST('test' AS int)`) containing sensitive data within error messages.
3. **Inferential / Blind SQLi**:
   - **Boolean-based**: Attacker asks true/false questions (`AND 1=1` vs `AND 1=2`), analyzing differences in page content.
   - **Time-based**: Attacker forces the DB to sleep (`WAITFOR DELAY '0:0:5'`, `pg_sleep(5)`), deducing information character-by-character based on latency.
4. **Out-of-Band (OOB) SQLi**: Forcing the database to resolve external DNS or SMB connections (`xp_dirtree`, `UTL_HTTP`) carrying extracted records.
5. **Second-Order / Remote Code Execution**: Storing payloads that trigger in background worker processes or escalating via MSSQL `xp_cmdshell`.

---

## 3. Telemetry & Detection Methods

### Required Log Sources
* **Web Application Firewall (WAF)**: AWS WAF, Cloudflare, ModSecurity audit logs.
* **Web Server Access Logs**: Nginx, Apache, IIS HTTP access logs containing URI query strings and POST bodies.
* **Database Audit Logs**: PostgreSQL `pgaudit`, MySQL General Query Log, MSSQL SQL Profiler/Extended Events.

### Concrete Detection Signatures

#### A. Sigma Rule: Web Server SQL Injection Patterns in Query String
```yaml
title: Potential SQL Injection Exploitation in HTTP Request
id: 8c3e8067-1fa2-43bb-bbd5-19e38d7a1234
status: production
description: Detects classic SQL injection syntax in web server access logs and URLs.
references:
    - https://owasp.org/www-community/attacks/SQL_Injection
logsource:
    category: webserver
detection:
    keywords_union:
        cs-method: 'GET'
        cs-uri-query|contains:
            - 'UNION%20SELECT'
            - 'UNION+SELECT'
            - 'union select'
    keywords_boolean:
        cs-uri-query|contains:
            - "' OR '1'='1"
            - "' OR 1=1--"
            - "admin'--"
    keywords_delay:
        cs-uri-query|contains:
            - 'pg_sleep('
            - 'WAITFOR+DELAY'
            - 'BENCHMARK('
    condition: 1 of keywords_*
fields:
    - c-ip
    - cs-method
    - cs-uri-stem
    - cs-uri-query
    - sc-status
level: high
tags:
    - attack.initial_access
    - attack.t1190
```

#### B. Splunk SPL: High-Volume Database Extraction Anomaly
```spl
index=db_audit sourcetype="postgresql:audit" statement="*SELECT*"
| bin _time span=5m
| stats count sum(rows_returned) as TotalRows by _time, user, client_ip
| where TotalRows > 50000 OR count > 2000
| eval Alert="Unusual Mass Record Exfiltration via Database Query"
| table _time, user, client_ip, count, TotalRows, Alert
```

#### C. ModSecurity / Snort Rule: Detecting Out-of-Band xp_cmdshell Invocation
```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SEC-ALERT MSSQL xp_cmdshell Execution Attempt in HTTP Request";
    flow:to_server,established;
    content:"xp_cmdshell"; nocase;
    pcre:"/(xp_cmdshell|sp_executesql)/i";
    classtype:web-application-attack;
    sid:2026003;
    rev:1;
)
```

---

## 4. Multi-Layered Defense & Mitigation Methods

### Preventative Controls (Secure Coding & Database Isolation)
1. **Parameterized Queries (Prepared Statements)**:
   - **Primary Defense**: Always separate code from data using parameterized queries across all database drivers.
   ```python
   # VULNERABLE:
   cursor.execute(f"SELECT * FROM users WHERE email = '{user_input}'")

   # SECURE (Parameterized):
   cursor.execute("SELECT * FROM users WHERE email = %s", (user_input,))
   ```
2. **Object-Relational Mapping (ORM) with Safe Bindings**:
   - Leverage vetted ORMs (SQLAlchemy, Prisma, Hibernate) while strictly avoiding raw SQL queries or dynamic fragment interpolation.
3. **Database Principle of Least Privilege**:
   - Web application database users must **never** possess DBA (`sa`, `postgres`, `root`) privileges.
   - Disable dangerous stored procedures (`xp_cmdshell`, `LOAD_FILE()`, `pg_read_file()`).
4. **WAF in Active Blocking Mode**:
   - Deploy managed WAF rules (OWASP Core Rule Set - CRS) configured to terminate anomalous requests at the edge.

---

# Attack #4: Server-Side Request Forgery (SSRF) & Cloud Metadata Theft

## 1. Executive Summary & Classification
* **Severity**: 🟥 **CRITICAL**
* **Typical Impact Score**: CVSS v3.1: 9.8 / 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`)
* **Primary Threat Vectors**: OWASP Top 10 - A10:2021 (Server-Side Request Forgery), Capital One Cloud Breach Model
* **Target Environment**: AWS EC2 / ECS / Lambda, Google Cloud Compute Engine (GCE), Azure VMs, Kubernetes Clusters

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Initial Access** | `T1190` | Exploit Public-Facing Application |
| **Credential Access** | `T1552.005` | Cloud Instance Metadata API |
| **Privilege Escalation** | `T1078.004` | Valid Cloud Accounts |
| **Lateral Movement** | `T1021` | Cloud VPC Pivoting & Internal Network Scanning |

---

## 2. Technical Attack Anatomy & Kill Chain Mechanics

SSRF occurs when a web application takes a user-supplied URL and makes an HTTP request on behalf of the attacker to internal or loopback resources:

```
[Attacker Request] ──► POST /api/fetch-preview {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role"}
                               │
                               ▼
[Cloud VM / Container] ──► Queries Link-Local Address (169.254.169.254)
                               │
                               ▼
[Cloud IMDS Service]   ──► Returns Temporary AWS STS Credentials:
                           AccessKeyId, SecretAccessKey, Token
                               │
                               ▼
[Attacker Host]        ──► Clones AWS Credentials into `aws-cli` and enumerates S3 buckets, RDS databases, and IAM policies!
```

### Critical Cloud Metadata Endpoints:
* **AWS EC2 (IMDSv1)**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`
* **Google Cloud Engine (GCE)**: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (bypassed if header validation is missing)
* **Azure VM**: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`
* **Kubernetes**: `https://kubernetes.default.svc/api/v1/namespaces/default/secrets`

---

## 3. Telemetry & Detection Methods

### Required Log Sources
* **Cloud Audit Logs (AWS CloudTrail / GCP Cloud Audit / Azure Activity Logs)**: API calls originating from outside the VPC where the IAM session name belongs to an EC2 instance profile.
* **VPC Flow Logs**: Internal traffic flowing to `169.254.169.254` or private RFC 1918 addresses from DMZ web servers.
* **Container & EDR Telemetry**: Falco / Sysmon for Linux tracking unexpected outbound curl/socket connections from web app pods.

### Concrete Detection Signatures

#### A. AWS CloudTrail CloudWatch / Athena Query: Role Credential Use from External IP
```sql
SELECT 
    eventTime, 
    userIdentity.sessionContext.sessionIssuer.userName AS RoleName,
    sourceIPAddress, 
    eventName, 
    awsRegion, 
    userAgent
FROM cloudtrail_logs
WHERE 
    userIdentity.type = 'AssumedRole'
    AND sourceIPAddress NOT LIKE '10.%'
    AND sourceIPAddress NOT LIKE '172.16.%'
    AND sourceIPAddress NOT LIKE '192.168.%'
    AND sourceIPAddress NOT IN ('<Corporate_Public_Gateway_IP>')
    AND eventName NOT IN ('AssumeRole', 'AssumeRoleWithSAML')
ORDER BY eventTime DESC;
```

#### B. Falco Rule (Kubernetes / Linux Container SSRF Detection)
```yaml
- rule: Outbound HTTP Connection to Cloud Metadata from Pod
  desc: Detects an outbound connection towards 169.254.169.254 from a container
  condition: >
    outbound and 
    fd.sip = "169.254.169.254" and 
    container and 
    not proc.name in (aws-iam-authenticator, cloud-init)
  output: "SSRF Attempt to Cloud Metadata: (user=%user.name command=%proc.cmdline container_id=%container.id dest_ip=%fd.sip)"
  priority: CRITICAL
  tags: [mitre_credential_access, cloud, ssrf]
```

---

## 4. Multi-Layered Defense & Mitigation Methods

### Preventative Controls
1. **Enforce AWS IMDSv2 (Session-Oriented Metadata Service)**:
   - IMDSv2 requires a `PUT` request with a special header `X-aws-ec2-metadata-token-ttl-seconds` to acquire a temporary token, followed by a `GET` with the token header.
   - **Crucial Setting**: Set the **Hop Limit to 1** on EC2 instances hosting containers (`HttpPutResponseHopLimit=1`), which prevents containerized workloads from reaching the host's metadata service.
2. **Network Egress Filtering**:
   - Block access to `169.254.169.254/32` at the host firewall level (`iptables` / Windows Filtering Platform) for application service accounts:
   ```bash
   iptables -A OUTPUT -m owner --uid-owner www-data -d 169.254.169.254 -j DROP
   ```
3. **Strict URL Parsing & Positive Allowlisting**:
   - Never allow arbitrary protocols (`file://`, `gopher://`, `dict://`).
   - Validate destination IP addresses against a strict domain whitelist and resolve DNS before checking against RFC 1918 private IP blocks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`).

---

# Attack #5: Distributed Denial of Service (DDoS) & L7 Application Exhaustion

## 1. Executive Summary & Classification
* **Severity**: 🟧 **HIGH / CRITICAL (Availability)**
* **Typical Impact Score**: CVSS v3.1: 7.5 - 8.6 / 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`)
* **Primary Threat Vectors**: Layer 4 Volumetric Floods (SYN, UDP Amplification), Layer 7 Application Attacks (HTTP/2 Rapid Reset CVE-2023-44487, Slowloris)
* **Target Environment**: Web applications, API Gateways, Public DNS Resolvers, Corporate Network Perimeters

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
| :--- | :--- | :--- |
| **Impact** | `T1498` | Network Denial of Service (Volumetric / Protocol Floods) |
| **Impact** | `T1499` | Endpoint Denial of Service (Application / Resource Exhaustion) |

---

## 2. Technical Attack Anatomy & Kill Chain Mechanics

Modern DDoS campaigns operate at two distinct layers of the OSI model:

```
[Layer 4 Volumetric Flood]  ──► 100+ Gbps UDP / DNS Reflection overwhelms network pipe bandwidth.
                                       OR
[Layer 7 Semantic Exhaustion] ──► 10,000 requests/sec targeting high-cost endpoints (e.g. `/api/generate-pdf` or `/search?q=*`)
                                       OR
[HTTP/2 Rapid Reset Attack]  ──► Client opens stream (`HEADERS` frame) and immediately resets it (`RST_STREAM` frame).
                                 Server wastes CPU allocating state without client waiting for reply!
```

### Attack Vectors:
1. **HTTP/2 Rapid Reset (CVE-2023-44487)**: Exploited in late 2023 to generate peak attacks of **398 million requests per second**. It bypasses standard rate limiters by aborting transactions before payload processing completes.
2. **Asymmetric Application-Layer Attacks**: Crafting lightweight HTTP requests that force the database or CPU to perform intensive operations (e.g., regex evaluation, cryptographic operations, unbounded SQL joins).
3. **Amplification Attacks (NTP, DNS, memcached)**: Spoofing victim IP to open UDP services that reply with 50x to 50,000x the initial request payload size.

---

## 3. Telemetry & Detection Methods

### Required Log Sources
* **CDN / Reverse Proxy Metrics**: Requests per second (RPS), HTTP 502/503/504 error ratios, RST stream rate counters.
* **NetFlow / IPFIX / sFlow**: Ingress packet rate (PPS), byte volume (BPS), protocol distribution (TCP vs UDP ratio).
* **Load Balancer Health Check Logs**: Backend latency spikes and instance failure state transitions.

### Concrete Detection Signatures

#### A. Splunk SPL: Detecting HTTP/2 Reset Anomaly & Layer-7 Outage
```spl
index=waf_proxy sourcetype="access_combined"
| bin _time span=1m
| stats count, count(eval(status>=500)) as ServerErrors, count(eval(http_version=="2.0" AND rst_stream=="true")) as RST_Count by _time, host
| eval ErrorRate = round((ServerErrors / count) * 100, 2)
| where RST_Count > 5000 OR (count > 20000 AND ErrorRate > 25)
| eval Status="CRITICAL: Severe DDoS or L7 Resource Starvation Active"
| table _time, host, count, ServerErrors, ErrorRate, RST_Count, Status
```

#### B. Suricata IDS: DNS Reflection Amplification Pattern
```suricata
alert udp any 53 -> $HOME_NET any (
    msg:"SEC-ALERT High-Volume DNS Amplification Response Flood";
    dsize:>1000;
    threshold: type both, track by_dst, count 500, seconds 2;
    classtype:denial-of-service;
    sid:2026005;
    rev:1;
)
```

---

## 4. Multi-Layered Defense & Mitigation Methods

### Preventative Controls & Edge Resilience
1. **Cloud Scrubbing & Anycast BGP Routing (Cloudflare, AWS Shield, Google Cloud Armor)**:
   - Ingest all public traffic through geographically distributed Anycast points of presence (PoPs) capable of absorbing tens of terabits per second.
2. **Patch & Mitigate HTTP/2 Rapid Reset**:
   - Update reverse proxies (Nginx 1.25.3+, Envoy, HAProxy) with stream concurrency limits and RST_STREAM rate-limiting directives.
3. **Adaptive Rate Limiting & CAPTCHA Challenges**:
   - Implement sliding-window rate limiters per IP, JA4 TLS fingerprint, and authenticated session token.
   - Enforce cryptographic Proof-of-Work (PoW) or Cloudflare Turnstile when request rates surpass baseline thresholds.
4. **Aggressive Timeout & Connection Tuning**:
   - Lower keep-alive timeouts and limit maximum concurrent unauthenticated connections to mitigate Slowloris.

---

# Universal Defense Architecture & Quick-Reference Matrix

| Attack Vector | Primary Detection Telemetry | Immediate Containment (First 15 Min) | Root Hardening Solution |
| :--- | :--- | :--- | :--- |
| **1. Ransomware** | Sysmon EID 1 (VSS wipe), Mass file modifications | EDR Host Network Isolation, Revoke `krbtgt` | Air-gapped Immutable Backups, WDAC Application Control |
| **2. Phishing (AiTM)** | Sign-in logs (Token replay, impossible travel) | Invalidate refresh tokens (`Revoke-AzureADUser...`) | FIDO2 Hardware Keys (WebAuthn), Compliant Device Policies |
| **3. SQL Injection** | WAF URI alerts, DB audit high row extraction | IP/Session block on WAF, DB read-only lock | Parameterized Queries (Prepared Statements), Least Privilege DB users |
| **4. SSRF & Metadata** | CloudTrail (IAM used from external IP), Egress to `169.254.169.254` | Detach IAM Instance Profile, Revoke STS sessions | Enforce IMDSv2 with Hop Limit 1, IPTables Link-Local Drop |
| **5. DDoS & L7 Floods** | NetFlow PPS spikes, RST stream metrics, 503 errors | Activate Cloud Scrubbing Under-Attack Mode | Anycast CDN, HTTP/2 Stream Limits, Adaptive Rate Limiting |

---

# Module 4: Password Security Reference Matrix (Attacks 31–39)

| # | Attack Name | Category | Primary MITRE | Key Detection Signal | Essential Countermeasure |
| :- | :--- | :--- | :--- | :--- | :--- |
| **31** | Brute-Force Attack | Password Attack | `T1110.001`, `T1078` | Event 4625 / 4740 lockout surges (>20/2min) | Smart Lockout, FIDO2 MFA, Adaptive WAF Rate Limits |
| **32** | Dictionary Attack | Password Attack | `T1110.001`, `T1110.002` | Event 4625 SubStatus `0xc000006a` clusters | Breached password screening (HaveIBeenPwned), 16+ chars |
| **33** | Credential Stuffing | Password Attack | `T1110.004`, `T1078` | WAF login surges (>85% failure) across proxy pools | Bot management (Cloudflare/Akamai), Universal MFA/Passkeys |
| **34** | Password Spraying | Password Attack | `T1110.003`, `T1078` | Event 4625 on >10 distinct users from single IP | Azure AD Password Protection, FIDO2, block legacy auth |
| **35** | Offline Password Cracking | Password Attack | `T1110.002`, `T1003.003` | Sysmon EID 1 `ntdsutil ifm` or `vssadmin shadows` | Memory-hard hashing (Argon2id), Tier 0 PAWs, Credential Guard |
| **36** | Rainbow Table Attack | Password Cracking | `T1110.002`, `T1552` | Mass read on DB hash columns, `rcrack.exe` execution | Cryptographic salts (128-bit), migrate away from NTLM/MD5 |
| **37** | Keylogger Attack | Password Cracking | `T1056.001`, `T1555` | `SetWindowsHookEx` WH_KEYBOARD_LL / GetAsyncKeyState | EDR API hook telemetry, password managers (autofill), FIDO2 |
| **38** | Hybrid Attack | Password Cracking | `T1110.002`, `T1003` | Hashcat execution with `-r` ruleset files | 20+ char passphrases, proactive internal AD password audits |
| **39** | Mask Attack | Password Cracking | `T1110.002`, `T1003` | Hashcat `-a 3` mask mode or `.hcmask` file presence | Length over complexity, passwordless (FIDO2 / Windows Hello) |

---

# Module 6: Operating System Security Reference Matrix (Attacks 65–83)

| # | Attack Name | Domain | Primary MITRE | Key Detection Signal | Essential Countermeasure |
| :- | :--- | :--- | :--- | :--- | :--- |
| **65** | Null Session Attack | Windows | `T1078.001`, `T1087.002` | Event 4624 Type 3 ANONYMOUS LOGON to IPC$ | `RestrictAnonymous = 2`, disable SMBv1 |
| **66** | Missing Patch Exploitation | Windows | `T1190`, `T1068` | Spoolsv/svchost spawning cmd.exe/powershell | Automated patch management (WSUS/Intune 72h SLA) |
| **67** | Privilege Escalation | Windows | `T1068`, `T1134` | Service account spawning SYSTEM cmd.exe | Strip SeImpersonatePrivilege, fix unquoted paths |
| **68** | Pass-the-Hash (PtH) | Windows | `T1550.002`, `T1003.001` | Event 4624 Type 3 NTLM KeyLength=0 | Credential Guard, LAPS, disable NTLMv1/v2 |
| **69** | Kerberoasting | Windows | `T1558.003`, `T1003` | Event 4769 RC4 (0x17) TGS spikes | Group Managed Service Accounts (gMSA), AES-256 |
| **70** | Linux NFS Attack | Linux | `T1021.002`, `T1548.001` | SUID binary creation on /mnt /nfs shares | Enforce `root_squash`, mount with `nosuid,nodev` |
| **71** | Linux Kernel Rootkit | Linux | `T1014`, `T1547.006` | auditd `init_module`/`finit_module` syscalls | UEFI Secure Boot, `kernel.modules_disabled=1` |
| **72** | Linux Privilege Escalation | Linux | `T1068`, `T1548.003` | Sudo GTFOBins commands, kernel page fault | Strict sudoers (no NOPASSWD), kernel livepatching |
| **73** | SSH Brute-Force | Linux | `T1110.001`, `T1021.004` | auth.log `Failed password` surges (>20/min) | `PasswordAuthentication no`, Fail2ban / CrowdSec |
| **74** | SUID Exploitation | Linux | `T1548.001`, `T1068` | execve with euid=0 spawned by GTFOBins | Strip SUID (`chmod u-s`), mount `/tmp` with `nosuid` |
| **75** | macOS Privilege Escalation | macOS | `T1548.002`, `T1068` | PrivilegedHelperTool spawning zsh/sh | Validate XPC client code signatures, enforce SIP |
| **76** | macOS Malware Attack | macOS | `T1204.002`, `T1555.001` | osascript `display dialog with hidden answer` | Gatekeeper, App Notarization, ESF-backed EDR |
| **77** | macOS Code Injection | macOS | `T1055.001`, `T1574.001` | `DYLD_INSERT_LIBRARIES` in process env | Hardened Runtime (`--options runtime`), Library Validation |
| **78** | Gatekeeper Bypass | macOS | `T1553.001`, `T1562.001` | `xattr -d com.apple.quarantine` execution | Rapid Security Responses (RSR), MDM enforcement |
| **79** | Launch Agent/Daemon Abuse | macOS | `T1543.001`, `T1543.004` | New `.plist` created in `~/Library/LaunchAgents` | Background Task Management (BTM), root directory locks |
| **80** | Specialized Buffer Overflow | OS Specialized | `T1203`, `T1059` | dmesg segfault, stack pivot, 0xc0000005 | ASLR, Full RELRO, Stack Canaries, memory-safe code |
| **81** | Specialized NFS Attack | OS Specialized | `T1021.002`, `T1212` | RPC write operations with non-privileged port | Enforce RPCSEC_GSS (Kerberos), `secure` export option |
| **82** | Race Condition Attack | OS Specialized | `T1068`, `T1574` | Rapid symlink/unlink loops (>500/sec) in /tmp | `fs.protected_symlinks=1`, atomic `O_CREAT\|O_EXCL` |
| **83** | Format String Attack | OS Specialized | `T1203`, `T1059` | Application SIGSEGV, %x/%n in inbound payload | `-Werror=format-security`, Full RELRO, explicit `%s` |

---
*Created for Enterprise Cyber Defense Teams & SOC Engineers. Keep updated with current threat intelligence.*

