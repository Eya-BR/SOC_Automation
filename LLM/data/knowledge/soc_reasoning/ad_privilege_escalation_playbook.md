# Active Directory Privilege Escalation Analysis Playbook

## 🎯 Core Analysis Framework

### **Step 1: Account Type Identification**
**CRITICAL**: Distinguish between human users and machine accounts before threat assessment.

#### **Machine Account Indicators:**
- Account ends with `$` (e.g., AD01$, SVC_SQL$, IIS_WPG$)
- Service accounts, system accounts, computer accounts
- Domain Controllers, servers, workstations
- Backup operators, monitoring agents

#### **Human Account Indicators:**
- Standard user accounts (no `$` suffix)
- Administrator accounts, privileged user accounts
- Service accounts used by humans

#### **Analysis Rules:**
```
IF account ends with "$":
    → Classify as MACHINE ACCOUNT
    → Validate if privilege usage is NORMAL for role
    → Check baseline behavior before escalation
ELSE:
    → Classify as HUMAN USER
    → Higher suspicion for privilege escalation
```

---

## 🏗️ Active Directory Privilege Usage Baselines

### **Domain Controller (DC) Normal Behavior:**
- **SeSecurityPrivilege**: Commonly assigned to DCs for:
  - Domain Controller operations
  - Active Directory management
  - Security auditing
  - Backup operations
  - Replication services
- **Expected Event IDs**: 4672, 4673, 4674 (normal DC operations)
- **Risk Level**: LOW for baseline DC operations

### **Server Normal Behavior:**
- **Administrative privileges**: Normal for server maintenance
- **Scheduled tasks**: Expected for automated operations
- **Service accounts**: Common for application functionality

### **Workstation Normal Behavior:**
- **Local admin rights**: Usually suspicious on workstations
- **Privilege escalation**: High suspicion unless authorized

---

## 🔍 Investigation Protocol

### **Phase 1: Asset Role Validation**
**Questions to Answer:**
1. Is AD01 a Domain Controller?
2. Is AD01 a server or workstation?
3. Is SeSecurityPrivilege normally assigned to this host?
4. Was there a recent GPO or service change?
5. Is this within a maintenance window?

### **Phase 2: Baseline Behavior Check**
**Validation Steps:**
1. Check Event ID patterns:
   - 4672, 4673, 4674 = Normal DC operations
   - 4688, 4697 = Suspicious process creation
2. Correlate with:
   - Group Policy changes
   - Service installations
   - Admin logon patterns
3. Time-based analysis:
   - Business hours vs after-hours activity
   - Scheduled task windows

### **Phase 3: Threat Classification**
```
BASELINE DC BEHAVIOR:
- Account: Machine ($ suffix)
- Privilege: SeSecurityPrivilege
- Host: Domain Controller
- Events: Normal DC operations (4672-4674)
→ CONCLUSION: LIKELY BENIGN

SUSPICIOUS INDICATORS:
- Account: Human user (no $ suffix)
- Privilege: Unexpected escalation
- Host: Workstation
- Events: Process creation (4688) without justification
→ CONCLUSION: LIKELY MALICIOUS
```

---

## 🎯 Correct MITRE ATT&CK Mapping

### **Privilege Escalation Decision Tree:**

#### **Scenario 1: Legitimate Privilege Assignment**
- **Technique**: T1098 - Account Manipulation
- **Use Case**: Legitimate admin assigns permissions
- **Indicators**: GPO changes, admin approval, change tickets
- **Confidence**: Medium

#### **Scenario 2: Valid Account Misuse**
- **Technique**: T1078 - Valid Accounts
- **Use Case**: Legitimate account used for malicious purposes
- **Indicators**: Unusual behavior patterns, after-hours activity
- **Confidence**: High

#### **Scenario 3: Exploitation-Based Escalation**
- **Technique**: T1068 - Exploitation for Privilege Escalation
- **Use Case**: Vulnerability exploit to gain higher privileges
- **Indicators**: Exploit evidence, suspicious process execution
- **Confidence**: Critical

---

## 🚫 False Positive Prevention

### **Common False Positive Scenarios:**
1. **Domain Controller Operations**
   - SeSecurityPrivilege on DC for legitimate management
   - Backup operators using admin rights
   - Replication services requiring elevated access

2. **Server Maintenance**
   - System updates requiring admin rights
   - Scheduled tasks with privileged operations
   - Application installation/deployment

3. **Service Account Operations**
   - Automated processes requiring system privileges
   - Monitoring agents performing security functions
   - Backup services with elevated access

### **Validation Questions:**
- "Is this behavior normal for the host's role?"
- "Was this activity authorized and documented?"
- "Does this deviate from established baseline?"
- "Are there corresponding change management records?"

---

## 📋 Investigation Checklist

### **Immediate Actions (First 30 Minutes):**
- [ ] Identify account type (human vs machine)
- [ ] Verify host role (DC, server, workstation)
- [ ] Check recent GPO/permission changes
- [ ] Correlate with scheduled tasks
- [ ] Validate maintenance windows
- [ ] Check for corresponding service tickets

### **Investigation Steps (First 2 Hours):**
- [ ] Review Security Event Log (4672, 4673, 4674, 4688, 4697)
- [ ] Analyze Group Policy modification history
- [ ] Check admin account logon patterns
- [ ] Correlate with system change logs
- [ ] Interview system administrators if human account
- [ ] Validate change management procedures

### **Containment Strategies:**
- [ ] **IF DC Account**: DO NOT revoke immediately - verify first
- [ ] **IF Human Account**: Consider temporary privilege reduction
- [ ] **IF Suspicious**: Implement enhanced monitoring
- [ ] Document all findings with timestamps

---

## 🎯 Decision Matrix

| Account Type | Host Role | Normal Behavior | Suspicious Indicators | Threat Level |
|--------------|------------|------------------|---------------------|-------------|
| Machine ($$) | DC | SeSecurityPrivilege | None | LOW |
| Machine ($$) | Server | Admin tasks | After-hours | MEDIUM |
| Human | Workstation | Local admin | Any | HIGH |
| Human | DC | Any | Process creation | CRITICAL |

---

## 📚 Standard Operating Procedures

### **Change Management Validation:**
1. Verify change request exists and approved
2. Confirm change was scheduled and documented
3. Check if implementer has proper authorization
4. Validate change window and business justification

### **Privilege Escalation Response:**
1. **Immediate**: Document findings, preserve evidence
2. **Assessment**: Determine legitimacy vs malicious intent
3. **Remediation**: Revoke if malicious, document if legitimate
4. **Prevention**: Update procedures, enhance monitoring

---

## ⚠️ Critical Warning

**NEVER classify machine account activity as "insider threat" without:**
1. Confirming it's not a Domain Controller
2. Validating normal baseline behavior
3. Checking for legitimate maintenance activities
4. Correlating with authorized changes

**Failure to follow this framework results in false positives and wasted investigation time.**
