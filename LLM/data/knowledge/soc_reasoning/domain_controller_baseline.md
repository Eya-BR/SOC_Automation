# Domain Controller Baseline Operations

## 🎯 Critical Knowledge: Normal DC Behavior

### **Expected Domain Controller Privileges**
- **SeSecurityPrivilege**: Standard for DC auditing and log management
- **SeBackupPrivilege**: Required for Active Directory backup operations
- **SeRestorePrivilege**: Needed for AD recovery and maintenance
- **SeDebugPrivilege**: Used by DC monitoring and troubleshooting tools

### **Normal DC Event Patterns**
- **Event ID 4672**: Special privileges assigned (normal DC operations)
- **Event ID 4673**: Sensitive privilege service invoked (expected)
- **Event ID 4674**: Sensitive privilege used (DC management)
- **Event ID 4768**: Kerberos TGS requests (normal authentication)
- **Event ID 4769**: Kerberos service ticket requests (expected)

### **DC Machine Account Behavior**
- **Account Pattern**: Machine accounts end with `$` (e.g., AD01$, DC01$)
- **Service Operations**: Automated DC maintenance and replication
- **Security Auditing**: Log collection and monitoring activities
- **Backup Operations**: Scheduled AD backup processes

---

## 🔍 Decision Framework for DC Alerts

### **Step 1: Account Type Validation**
```
IF account ends with "$"
   → Classify as MACHINE ACCOUNT
   → Lower initial suspicion level
ELSE
   → Classify as HUMAN USER
   → Higher suspicion for privilege escalation
```

### **Step 2: Host Role Assessment**
```
IF host name indicates Domain Controller
   → Expect elevated privilege usage
   → Validate against DC baseline behavior
ELSE IF host is server
   → Check if privilege matches server role
   → Verify maintenance window context
ELSE
   → Higher suspicion for privilege escalation
```

### **Step 3: Privilege Normalization**
```
IF privilege = SeSecurityPrivilege AND host = DC
   → LIKELY BENIGN (normal DC operations)
   → Document as expected behavior
IF privilege = SeBackupPrivilege AND time = backup window
   → LIKELY BENIGN (scheduled backup)
   → Verify backup schedule
IF privilege is NEW to account
   → INVESTIGATE (potential escalation)
   → Check change management records
```

---

## 🚫 False Positive Prevention for DCs

### **Common False Positive Scenarios:**

#### **Scenario 1: DC Auditing Operations**
**Alert**: Machine account using SeSecurityPrivilege
**Reality**: Normal DC log collection and auditing
**Validation**: Check if time corresponds to scheduled log collection
**Action**: Document as normal DC operations

#### **Scenario 2: AD Replication**
**Alert**: DC account performing privileged operations
**Reality**: Normal Active Directory replication between DCs
**Validation**: Correlate with replication schedules
**Action**: Document as expected replication activity

#### **Scenario 3: Backup Operations**
**Alert**: DC account using backup privileges
**Reality**: Scheduled Active Directory backup
**Validation**: Check backup schedule and change management
**Action**: Document as authorized backup operations

#### **Scenario 4: Maintenance Activities**
**Alert**: DC account with elevated privileges
**Reality**: Planned DC maintenance or updates
**Validation**: Verify maintenance window and change tickets
**Action**: Document as authorized maintenance

---

## 📋 Investigation Checklist for DC Alerts

### **Immediate Validation (First 5 Minutes):**
- [ ] Account ends with `$`? (Machine account)
- [ ] Host is Domain Controller? (AD01, DC01 pattern)
- [ ] Privilege is normal for DCs? (SeSecurityPrivilege, SeBackupPrivilege)
- [ ] Time corresponds to maintenance window?
- [ ] Recent change management activities?

### **Baseline Analysis (First 30 Minutes):**
- [ ] Compare with historical DC behavior patterns
- [ ] Check for corresponding replication events
- [ ] Verify backup schedule alignment
- [ ] Review Group Policy processing times
- [ ] Correlate with other DC activities

### **Documentation Requirements:**
- [ ] Document as "Expected DC Operations" if benign
- [ ] Note any deviations from normal patterns
- [ ] Record baseline comparison results
- [ ] Include change management references
- [ ] Specify monitoring recommendations

---

## 🎯 Professional Classification Rules

### **Classification Decision Tree for DCs:**

```
DC Alert Analysis:
    ↓
Account Type: Machine ($ suffix)?
    ├─ Yes → Lower suspicion
    │   ├─ Host is Domain Controller?
    │   │   ├─ Yes → Check privilege normality
    │   │   │   ├─ SeSecurityPrivilege? → LIKELY BENIGN
    │   │   │   ├─ SeBackupPrivilege? → LIKELY BENIGN
    │   │   │   └─ Other privilege? → INVESTIGATE
    │   │   └─ No → Check server role
    │   └─ No → Higher suspicion (human user)
    └─ No → Standard user analysis
```

### **Severity Assignment for DCs:**
- **LOW**: Machine account + normal DC privilege + expected time
- **MEDIUM**: Machine account + unusual privilege + needs validation
- **HIGH**: Human user + DC access + suspicious behavior
- **CRITICAL**: Confirmed malicious DC compromise

---

## ⚠️ Critical Response Rules

### **NEVER:**
- Revoke DC privileges without validation
- Isolate Domain Controller based on single alert
- Assume malicious intent without evidence
- Respond to DC alerts without understanding baseline

### **ALWAYS:**
- Validate account type and host role first
- Compare against normal DC behavior patterns
- Check maintenance windows and change management
- Document baseline validation results
- Consider business impact of DC disruptions

---

## 🎓 Senior Analyst DC Mindset

### **Key Principles:**
- **DCs are special**: Different rules apply to Domain Controllers
- **Privileges are expected**: DCs legitimately use high privileges
- **Baseline is critical**: Understand normal before calling anomaly
- **Business impact matters**: DC disruptions affect entire organization

### **Common Pitfalls:**
- **Over-reacting to DC alerts**: Most DC privilege usage is normal
- **Ignoring account type**: Machine accounts behave differently
- **Missing maintenance context**: Scheduled activities appear suspicious
- **Forgetting replication**: Normal DC operations look like attacks

**This baseline knowledge prevents false positives and ensures appropriate DC alert handling.**
