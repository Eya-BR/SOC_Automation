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

Domain Controller normal behavior includes SeSecurityPrivilege, Event IDs 4672-4674. Service accounts perform legitimate automated operations. Business operations include maintenance windows, change management, seasonal patterns. Professional triage: Rapid context assessment → Quick validation → Detailed analysis → Decision making with business impact consideration.

**Tags:** enterprise, context, business, operations, triage, risk  
**Category:** privilege_escalation

## 🎯 Professional Triage Process

### **Step 1: Rapid Context Assessment (First 2 Minutes)**
-- **Account Type**: Machine vs Human
-- **Host Role**: DC, Server, Workstation  
-- **Activity Type**: Normal vs Suspicious

### **Step 2: Quick Validation (Next 3 Minutes)**
-- **Baseline Validation**: Comparison with normal behavior
-- **Context Verification**: Business justification check
-- **Authorization Confirmation**: Change management validation
-- **Risk Assessment**: Professional threat determination

### **ALWAYS Document:**
1. **Analysis Steps**: What was examined and why
2. **Evidence Sources**: RAG, VirusTotal, LLM analysis
3. **Context Factors**: Account type, host role, business context
4. **Risk Determination**: How threat level was calculated
5. **Business Impact**: Operational and security implications

### **Step 3: Detailed Analysis (Next 5 Minutes)**
-- **Technical Analysis**: Event details and patterns
-- **Threat Classification**: Benign, Suspicious, Malicious
-- **Risk Assessment**: Business impact and urgency
-- **Response Planning**: Immediate actions needed
-- **Documentation**: Complete analysis record

### **Step 4: Decision Making (First 1 Hour)**
-- **Threat Classification**: Benign, Suspicious, Malicious
-- **Risk Assessment**: Business impact and urgency
-- **Response Planning**: Immediate actions needed
-- **Documentation**: Complete analysis record

## 📊 Enterprise Risk Assessment

### **Risk Factors by Context**
-- **Machine Accounts**: Lower risk baseline
-- **Domain Controllers**: Expected elevated privileges
-- **Service Accounts**: Automated operations context
-- **Human Accounts**: Higher risk assessment
-- **Business Hours**: Normal vs after-hours
-- **Change Management**: Authorized modifications

## 📋 Clean Analysis Output Structure

### **✅ Final Output Format:**
```json
{
  "alert_id": "unknown",
  "analysis_timestamp": "...",
  "source": {
    "system": "Splunk",
    "rule": "AD - Privilege Escalation Detected",
    "source_severity": "high"
  },
  "threat_score": 0.3,
  "overall_severity": "low",
  "observables": {...},
  "virustotal_analysis": {...},
  "llm_enrichment": {
    "hypothesis": "SeSecurityPrivilege usage detected on host AD01",
    "confidence": 0.2,
    "note": "Machine account (AD01$) detected, activity may be legitimate",
    "recommendations": {
      "immediate_actions": ["Verify machine account activity is expected"],
      "investigation_steps": ["Review service configuration"],
      "containment_strategies": [],
      "prevention_measures": ["Implement principle of least privilege"]
    }
  },
  "summary": "Splunk: AD - Privilege Escalation Detected | LLM: SeSecurityPrivilege usage detected on host AD01 | Severity: low"
}
```

### **✅ Key Principles:**
- **No duplicate blocks** - Single clean structure
- **No hallucinations** - Evidence-based analysis only
- **Context-aware** - Account type and host role consideration
- **Professional triage** - Structured decision-making process
- **Business impact focus** - Operational implications

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
