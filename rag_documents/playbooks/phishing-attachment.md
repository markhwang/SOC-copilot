# Incident Response Playbook: Phishing with Malicious Attachment

**Playbook ID**: IR-PHISH-001  
**Version**: 2.1  
**Last Updated**: 2025-01-15  
**Owner**: Security Operations  
**MITRE ATT&CK**: T1566.001 (Spearphishing Attachment)

---

## 1. Overview

This playbook provides step-by-step guidance for responding to phishing emails containing malicious attachments. It covers detection, containment, eradication, and recovery phases.

### Scope
- Emails with executable attachments (.exe, .scr, .bat, .ps1, .vbs, .js)
- Emails with macro-enabled documents (.docm, .xlsm, .pptm)
- Emails with archive files containing malicious payloads (.zip, .rar, .7z)
- Emails with PDF files containing embedded scripts or links

### Severity Classification

| Indicator | Severity | Response Time |
|-----------|----------|---------------|
| Attachment opened/executed | Critical | 15 minutes |
| Attachment downloaded, not opened | High | 1 hour |
| Email received, no user action | Medium | 4 hours |
| Email blocked by gateway | Low | 24 hours |

---

## 2. Detection

### Alert Sources
- Microsoft Defender for Office 365 (Safe Attachments)
- Email Security Gateway (Proofpoint, Mimecast)
- Microsoft Sentinel Analytics Rules
- User reports (phishing button)

### Key Indicators

**Email Indicators**:
- External sender with spoofed display name
- Sender domain age < 30 days
- Reply-to differs from From address
- Urgent/threatening language in subject
- Unexpected attachment from known sender

**Attachment Indicators**:
- Double extension (invoice.pdf.exe)
- Macro-enabled Office document
- Password-protected archive
- Executable in archive
- Known malware hash

### Sentinel Detection Rule (KQL)

```kql
// Detect emails with suspicious attachments
EmailAttachmentInfo
| where TimeGenerated > ago(1h)
| where FileType in~ ("exe", "scr", "bat", "ps1", "vbs", "js", "docm", "xlsm")
    or FileName endswith ".pdf.exe"
    or FileName endswith ".doc.exe"
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(1h)
    | where EmailDirection == "Inbound"
) on NetworkMessageId
| project
    TimeGenerated,
    RecipientEmailAddress,
    SenderFromAddress,
    Subject,
    FileName,
    FileType,
    SHA256
```

---

## 3. Initial Triage (15 minutes)

### Step 1: Gather Alert Context
- [ ] Identify recipient(s) of the email
- [ ] Identify sender address and domain
- [ ] Obtain attachment hash (SHA256)
- [ ] Check if attachment was opened (Defender for Endpoint events)

### Step 2: Check Threat Intelligence
- [ ] Search attachment hash in VirusTotal
- [ ] Search sender domain in threat intel feeds
- [ ] Check if sender IP is in known malicious list
- [ ] Look for related campaigns in threat intel reports

### Step 3: Assess Blast Radius
- [ ] How many users received this email?
- [ ] How many users opened the attachment?
- [ ] Are any executive/VIP users affected?
- [ ] Are any critical system admins affected?

### Triage Decision Matrix

| Attachment Opened? | Hash Known Malicious? | Action |
|--------------------|----------------------|--------|
| Yes | Yes | CRITICAL - Immediate containment |
| Yes | No/Unknown | HIGH - Investigate endpoint |
| No | Yes | HIGH - Delete email, block sender |
| No | No/Unknown | MEDIUM - Analyze attachment |

---

## 4. Containment (30 minutes)

### If Attachment Was Opened:

**Immediate Actions (Parallel)**:

1. **Isolate Endpoint**
   ```
   Defender for Endpoint > Device > Isolate Device
   ```
   - Select "Full isolation" to block all network except Defender
   - Document isolation time

2. **Disable User Account** (if credential theft suspected)
   ```powershell
   # Azure AD / Entra ID
   Set-AzureADUser -ObjectId "user@company.com" -AccountEnabled $false
   
   # Revoke sessions
   Revoke-AzureADUserAllRefreshToken -ObjectId "user@company.com"
   ```

3. **Block Sender Domain**
   - Add to email gateway block list
   - Add to Defender for Office 365 Tenant Allow/Block List

4. **Delete Email from All Mailboxes**
   ```powershell
   # Content Search and Purge
   New-ComplianceSearch -Name "Phishing-$(Get-Date -Format yyyyMMdd)" `
       -ExchangeLocation All `
       -ContentMatchQuery "from:malicious@domain.com AND subject:'Invoice'"
   Start-ComplianceSearch -Identity "Phishing-$(Get-Date -Format yyyyMMdd)"
   # After search completes:
   New-ComplianceSearchAction -SearchName "Phishing-$(Get-Date -Format yyyyMMdd)" -Purge -PurgeType HardDelete
   ```

### If Attachment Was NOT Opened:

1. **Delete Email from Mailboxes** (as above)
2. **Block Sender Domain**
3. **Notify Affected Users** (awareness, not alarm)
4. **Add Indicators to Block Lists**
   - Attachment hash to Defender for Endpoint custom indicators
   - Sender domain to email gateway
   - Any URLs in email body to web proxy

---

## 5. Investigation (1-4 hours)

### Endpoint Analysis (if attachment opened)

**Query 1: Process Execution from Email Attachment**
```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where DeviceId == "<affected_device_id>"
| where InitiatingProcessFileName in~ ("outlook.exe", "winword.exe", "excel.exe")
| project TimeGenerated, FileName, ProcessCommandLine, SHA256, AccountName
| order by TimeGenerated asc
```

**Query 2: Network Connections Post-Execution**
```kql
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where DeviceId == "<affected_device_id>"
| where InitiatingProcessFileName == "<malicious_process>"
| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by TimeGenerated asc
```

**Query 3: File Modifications**
```kql
DeviceFileEvents
| where TimeGenerated > ago(24h)
| where DeviceId == "<affected_device_id>"
| where InitiatingProcessFileName == "<malicious_process>"
| where ActionType in ("FileCreated", "FileModified")
| project TimeGenerated, FileName, FolderPath, SHA256
```

**Query 4: Registry Modifications (Persistence)**
```kql
DeviceRegistryEvents
| where TimeGenerated > ago(24h)
| where DeviceId == "<affected_device_id>"
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any ("Run", "RunOnce", "Services")
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
```

### Malware Analysis

1. **Sandbox Analysis**
   - Submit attachment to sandbox (Joe Sandbox, Any.Run, Hybrid Analysis)
   - Document observed behaviors:
     - [ ] Network connections (C2)
     - [ ] File drops
     - [ ] Registry modifications
     - [ ] Process injection
     - [ ] Credential access attempts

2. **Extract Indicators**
   - C2 domains/IPs
   - Dropped file hashes
   - Mutex names
   - Registry keys

### User Interview

Contact affected user to determine:
- [ ] Did they expect this email?
- [ ] Did they open the attachment? When?
- [ ] Did they enter any credentials?
- [ ] Did they notice anything unusual afterward?
- [ ] Did they forward the email to anyone?

---

## 6. Eradication

### Endpoint Remediation

1. **Remove Malware**
   ```
   Defender for Endpoint > Device > Run Antivirus Scan > Full Scan
   ```
   - If malware persists, consider reimaging

2. **Remove Persistence Mechanisms**
   - Delete registry run keys
   - Remove scheduled tasks
   - Delete dropped files

3. **Reset Credentials** (if credential theft suspected)
   - Reset user password
   - Reset service account passwords if accessed
   - Rotate API keys/tokens

### Environment Hardening

1. **Block All Extracted IOCs**
   - Hashes → Defender for Endpoint custom indicators
   - Domains/IPs → Firewall/Proxy block
   - URLs → Web gateway block

2. **Hunt for Additional Compromise**
   ```kql
   // Search for same malware hash across environment
   DeviceFileEvents
   | where TimeGenerated > ago(7d)
   | where SHA256 == "<malware_hash>"
   | summarize AffectedDevices = make_set(DeviceName)
   ```

---

## 7. Recovery

### Restore User Access

1. **Re-enable User Account** (after password reset)
2. **Release Endpoint from Isolation**
3. **Verify Endpoint Health**
   - Full AV scan clean
   - No persistence mechanisms
   - Normal network behavior

### Communication

1. **Notify User**
   - Explain what happened (without blame)
   - Remind of phishing indicators
   - Provide phishing reporting mechanism

2. **Update Stakeholders**
   - Incident ticket with timeline
   - Brief management if significant impact

---

## 8. Lessons Learned

### Post-Incident Review

- [ ] How did the email bypass filters?
- [ ] Could detection have been faster?
- [ ] Were playbook steps effective?
- [ ] What additional controls would help?

### Improvement Actions

| Gap Identified | Action | Owner | Due Date |
|----------------|--------|-------|----------|
| Email filter gap | Tune Safe Attachments policy | Email Admin | +7 days |
| Slow detection | Add Sentinel rule for pattern | Detection Eng | +14 days |
| User clicked | Schedule phishing training | Security Awareness | +30 days |

---

## 9. Escalation Criteria

Escalate to Incident Commander / L3 if:
- [ ] More than 10 users opened attachment
- [ ] Executive/VIP compromised
- [ ] Evidence of lateral movement
- [ ] Data exfiltration detected
- [ ] Ransomware indicators observed

**Escalation Contact**: security-incident@company.com / (555) 123-4567

---

## 10. References

- MITRE ATT&CK: [T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- Microsoft: [Investigate malicious email](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/investigate-malicious-email-that-was-delivered)
- NIST: [Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
