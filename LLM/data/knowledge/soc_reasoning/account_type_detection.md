# Account Type Detection Logic

## 🎯 Machine vs Human Account Detection

### **Machine Account Indicators:**
- Account ends with `$` (e.g., AD01$, SVC_SQL$, IIS_WPG$)
- Service accounts, system accounts, computer accounts
- Domain Controllers, servers, workstations
- Backup operators, monitoring agents

### **Human Account Indicators:**
- Standard user accounts (No `$` suffix)
- Administrator accounts, privileged user accounts
- Service accounts used by humans

### **Analysis Rules:**
```
IF account ends with "$":
    → Classify as MACHINE ACCOUNT
    → Validate if privilege usage is NORMAL for role
    → Check baseline behavior before escalation
ELSE:
    → Classify as HUMAN USER
    → Higher suspicion for privilege escalation
```

### **Domain Controller Behavior:**
- **SeSecurityPrivilege**: Commonly assigned to DCs for:
  - Domain Controller operations
  - Active Directory management
  - Security auditing
  - Backup operations
  - Replication services
- **Expected Event IDs**: 4672, 4673, 4674 (normal DC operations)
- **Risk Level**: LOW for baseline DC operations

### **False Positive Prevention:**
- **NEVER classify machine account activity as "insider threat" without:
  1. Confirming it's not a Domain Controller
  2. Validating normal baseline behavior
  3. Checking for legitimate maintenance activities

### **Investigation Questions:**
1. Is this a Domain Controller?
2. Is this a machine account (ends with $)?
3. Is this normal behavior for the host role?
4. Was there a recent authorized change?
