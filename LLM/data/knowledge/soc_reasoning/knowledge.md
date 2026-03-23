# SOC Knowledge Base

## PowerShell Malware

Malicious PowerShell often uses encoded commands, bypass techniques, and living-off-the-land binaries.

**Tags:** powershell, malware, encoded, obfuscation  
**Category:** malware

---

## SSH Brute Force

SSH brute force attacks involve repeated failed login attempts from same or multiple IPs.

**Tags:** ssh, brute, force, failed, login  
**Category:** credential_access

---

## Phishing Indicators

Phishing emails often contain urgent language, suspicious links, and unexpected attachments.

**Tags:** phishing, email, link, attachment, urgent  
**Category:** initial_access

---

## Lateral Movement

Lateral movement involves remote access tools, pass-the-hash, and network traversal.

**Tags:** lateral, movement, remote, psexec, smb  
**Category:** lateral_movement

---

## Data Exfiltration

Data exfiltration involves large transfers, unusual destinations, and encrypted channels.

**Tags:** exfiltration, data, transfer, external, upload  
**Category:** exfiltration

---

## Privilege Escalation

Privilege escalation exploits system vulnerabilities, misconfigurations, and weak permissions.

**Tags:** escalation, privilege, admin, sudo, uac, vulnerability  
**Category:** privilege_escalation

---

## Persistence

Persistence mechanisms include scheduled tasks, registry modifications, and startup programs.

**Tags:** persistence, startup, registry, scheduled, service  
**Category:** persistence

---

## Reconnaissance

Reconnaissance involves port scanning, enumeration, and information gathering.

**Tags:** reconnaissance, scanning, enumeration, discovery, port  
**Category:** reconnaissance

---

## Malware Families

Common malware families include Emotet, TrickBot, Ryuk, and WannaCry with specific behaviors.

**Tags:** malware, emotet, trickbot, ryuk, wannacry  
**Category:** malware

---

## Web Attacks

Web attacks include SQL injection, XSS, CSRF, and file upload vulnerabilities.

**Tags:** web, sql, injection, xss, csrf, upload  
**Category:** initial_access

---

## Network Anomalies

Network anomalies include unusual traffic patterns, port scans, and protocol violations.

**Tags:** network, anomaly, traffic, scan, protocol  
**Category:** reconnaissance

---

## Insider Threats

Insider threats involve unauthorized access, data theft, and privilege abuse by trusted users.

**Tags:** insider, trusted, unauthorized, theft, abuse  
**Category:** privilege_escalation

---

## Advanced Persistent Threats

Advanced Persistent Threats use sophisticated techniques, custom malware, and long-term access.

**Tags:** apt, advanced, persistent, sophisticated, custom  
**Category:** persistence

---

## SOC Analytic Framework

SOC Analyst Framework: Assume innocent until proven guilty. False positive first mentality. Account type intelligence: Machine accounts ($ suffix) usually legitimate, Domain Controllers expected to use high privileges. Only escalate if ALL conditions met: human account + suspicious behavior + no authorization + baseline deviation. Document uncertainty and confidence levels.

**Tags:** soc, analyst, framework, false_positive, context, baseline  
**Category:** privilege_escalation

---

## Enterprise Context Analysis

Enterprise Context Analysis: Domain Controller normal behavior includes SeSecurityPrivilege, Event IDs 4672-4674. Service accounts perform legitimate automated operations. Business operations include maintenance windows, change management, seasonal patterns. Professional triage: Rapid context assessment → Quick validation → Detailed analysis → Decision making with business impact consideration.

**Tags:** enterprise, context, business, operations, triage, risk  
**Category:** privilege_escalation

---

## Domain Controller Baseline

Domain Controller Baseline Operations: SeSecurityPrivilege is standard for DC auditing and log management. Machine accounts end with $. Event IDs 4672-4674 are normal DC operations. DC machine account with SeSecurityPrivilege is likely benign - document as expected behavior. Never revoke DC privileges without validation.

**Tags:** domain, controller, baseline, sesecurityprivilege, machine, account, benign  
**Category:** privilege_escalation

---

## Account Type Detection

Machine vs Human Account Detection: Machine accounts end with $ (AD01$, SVC_SQL$), human accounts have no suffix. Domain Controllers commonly use SeSecurityPrivilege. Check baseline behavior before threat classification. NEVER classify machine account activity as insider threat without validation.

**Tags:** account, detection, machine, human, baseline, false_positive  
**Category:** privilege_escalation

---

## False Positive Prevention

False Positive Prevention: Validate account type, host role, baseline behavior, and authorization before classification. Common scenarios: DC operations (Event 4672-4674), server maintenance, service accounts, backup operations. Always document validation steps and decision rationale. Consider business impact of false positives.

**Tags:** false_positive, prevention, validation, soc, triage, business  
**Category:** privilege_escalation
