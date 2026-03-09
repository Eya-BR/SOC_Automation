# SOC Analyst Framework

## 🎯 Analytic Principles

### **Core Analytic Principles**

#### **1. Assume Innocent Until Proven Guilty**
- **Default Position**: Most alerts are legitimate business operations
- **Burden of Proof**: Must prove malicious intent, not assume it
- **Context First**: Understand environment before classification
- **Baseline Validation**: Compare against normal operational patterns

#### **2. False Positive First Mentality**
- **Question Everything**: "Is this expected behavior?"
- **Business Context**: Consider legitimate business operations
- **Change Management**: Was this authorized and documented?
- **Operational Windows**: Does this fit maintenance schedules?

#### **3. Account Type Intelligence**
- **Machine Accounts ($ suffix)**: Usually legitimate automated operations
- **Domain Controllers**: Expected to use high privileges for normal operations
- **Service Accounts**: Automated processes requiring system access
- **Human Accounts**: Higher suspicion for privilege escalation

---

## 🔍 Senior Analyst Decision Framework

### **Phase 1: Contextual Analysis**
**Questions to Answer Before Classification:**
1. **What is the account type?** (Machine vs Human)
2. **What is the host's normal role?** (DC, Server, Workstation)
3. **Is this behavior normal for this role?** (Baseline validation)
4. **Was this activity authorized?** (Change management)
5. **Is there a legitimate business reason?** (Operational context)

### **Phase 2: Threat Assessment**
**Only escalate if ALL conditions met:**
- Account type indicates high risk (human user)
- Host role doesn't justify the activity
- Behavior deviates from established baseline
- No authorization or business justification
- Correlates with suspicious indicators

### **Phase 3: Investigation Priority**
**Triage Priority Matrix:**
- **CRITICAL**: Human account + suspicious behavior + no authorization
- **HIGH**: Human account + unusual behavior + questionable context
- **MEDIUM**: Machine account + unexpected behavior + no baseline
- **LOW**: Machine account + normal behavior + legitimate context

---

## 🚫 False Positive Prevention Rules

### **Common False Positive Scenarios:**

#### **Domain Controller Operations**
- **SeSecurityPrivilege on DC**: Normal for AD management
- **Event IDs 4672-4674**: Expected DC operations
- **Replication traffic**: Normal AD behavior
- **Group Policy changes**: Authorized administrative activity

#### **Server Maintenance**
- **Scheduled tasks**: Automated legitimate operations
- **Service account usage**: Expected application behavior
- **Backup operations**: Authorized data protection
- **Patch deployment**: Planned maintenance activities

#### **Service Account Operations**
- **Automated processes**: Repetitive predictable patterns
- **Monitoring agents**: Security tool functionality
- **Application services**: Legitimate business operations

---

## 📋 Investigation Playbook

### **Step 1: Immediate Validation (First 5 Minutes)**
- [ ] Identify account type (machine vs human)
- [ ] Determine host role and normal function
- [ ] Check for recent authorized changes
- [ ] Verify business hours vs activity time
- [ ] Look for change management tickets

### **Step 2: Baseline Analysis (First 30 Minutes)**
- [ ] Review historical behavior patterns
- [ ] Check for similar past activities
- [ ] Validate against operational baselines
- [ ] Correlate with system events
- [ ] Interview system administrators if needed

### **Step 3: Threat Determination (First 2 Hours)**
- [ ] Document all findings with timestamps
- [ ] Assess risk based on context and deviation
- [ ] Determine if escalation is warranted
- [ ] Prepare detailed investigation report
- [ ] Recommend appropriate response actions

---

## 🎯 Professional Classification Guidelines

### **Classification Decision Tree:**

```
START: Alert Received
    ↓
Account Type Analysis:
    ├─ Machine Account ($ suffix)
    │   ├─ Domain Controller?
    │   │   ├─ Yes → LIKELY BENIGN (document)
    │   │   └─ No → Validate baseline
    │   └─ Server/Workstation?
    │       ├─ Yes → Check authorization
    │       └─ No → Investigate further
    └─ Human Account
        ├─ Privileged User?
        │   ├─ Yes → Verify authorization
        │   └─ No → Higher suspicion
        └─ Standard User?
            ├─ Privilege escalation?
            │   ├─ Yes → INVESTIGATE
            │   └─ No → Standard procedure
```

### **Severity Assignment Logic:**
- **LOW**: Machine account + normal behavior + legitimate context
- **MEDIUM**: Machine account + unusual behavior + needs validation
- **HIGH**: Human account + suspicious behavior + questionable context
- **CRITICAL**: Human account + confirmed malicious + immediate action needed

---

## ⚠️ Critical Senior Analyst Rules

### **NEVER Classify as Threat Without:**
1. **Account Type Understanding**: Machine vs human analysis
2. **Baseline Validation**: Comparison with normal behavior
3. **Context Verification**: Business justification check
4. **Authorization Confirmation**: Change management validation
5. **Risk Assessment**: Professional threat determination

### **ALWAYS Document:**
1. **Analysis Steps**: What was examined and why
2. **Decision Rationale**: How conclusion was reached
3. **Evidence Collected**: Logs, tickets, interviews
4. **Uncertainty Factors**: What couldn't be validated
5. **Recommendation Logic**: Why specific actions recommended

### **Professional Standards:**
- **Assume legitimate until proven malicious**
- **Consider business impact of false positives**
- **Maintain objective, evidence-based analysis**
- **Document uncertainty and confidence levels**
- **Escalate only with sufficient evidence**

---

## 🎓 Senior Analyst Mindset

### **Key Principles:**
- **Context over indicators**: Understand the environment first
- **Baseline over alerts**: Compare against normal operations
- **Evidence over assumptions**: Require proof of malicious intent
- **Business impact over detection**: Consider operational disruption
- **Professional judgment over automated rules**: Apply human reasoning

### **Common Pitfalls to Avoid:**
- **Alert fatigue**: Don't become desensitized to alerts
- **Automation bias**: Don't trust tools without validation
- **False positive blindness**: Don't miss real threats avoiding false alarms
- **Over-reliance on indicators**: Context matters more than individual events
- **Premature escalation**: Complete analysis before response

**This framework ensures professional, context-aware security analysis that minimizes false positives while maintaining threat detection effectiveness.**
