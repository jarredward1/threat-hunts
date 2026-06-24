# Hunt 08: Second Vector
### M365 Compromise & Business Email Compromise

```
Incident   : 87241
Workspace  : law-cyber-range (Microsoft Sentinel)
Platform   : Microsoft 365 · Entra ID · Defender XDR
Window     : 2026-06-11 03:00 to 13:00 UTC
Flags      : 38 across multiple stages
Difficulty : Intermediate · T2
Hunter     :
Date       :
```

---

## Scenario

Overnight, Microsoft Entra ID Protection raised Incident 87241 against a finance user: a sign-in from an anonymous IP, flagged on `m.smith`, rated **Low**. The night shift triaged it, found nothing actionable, and left it in the queue.

This is a cloud-only intrusion. No malware, no endpoint to image. Everything the attacker did was through identity, mail, files, and cloud services, and every action left a trace in a different table. The investigation spans sign-in logs, mailbox audit, Graph activity, and mail events.

**What the night shift could not answer:**

- Whether the Low rating is correct, or whether the machine dismissed a full compromise
- What the operator did once inside, and what they took
- What persisted, and whether it still acts with nobody signed in
- Who else was drawn into the fraud, and how

The detection caught one sign-in. It did not ask what happened next. That is your job.

---

## Data Dictionary

| Table | Contents |
|---|---|
| `SigninLogs` | Entra ID sign-ins: auth outcome, source, client app, conditional access, MFA |
| `AuditLogs` | Entra directory changes: config and identity-object activity |
| `CloudAppEvents` | Defender for Cloud Apps: file and mailbox operations, cloud-service actions |
| `OfficeActivity` | Office 365 unified audit: mailbox actions, rule operations, file activity |
| `MicrosoftGraphActivityLogs` | Microsoft Graph API calls: programmatic requests against the tenant |
| `EmailEvents` | Defender for Office 365 mail flow: messages sent and received |
| `IdentityLogonEvents` | Defender for Identity: account logons across the identity estate |
| `BehaviorAnalytics` | Entra UEBA derived signals: anomaly scoring on sign-in activity |

> Query via Sentinel > Logs > KQL. Use `TableName | take 1` for a sample row, `TableName | getschema` for columns.

---

## Stage 00: Incident Handoff

### Q00: Acceptance Gate

**Question:** Acknowledge readiness with the phrase from the IR Brief.

**Answer:** `Tier-2 hunter ready`

**Screenshot**

<!-- ![Q00](screenshots/q00.png) -->

---

## Stage 01: Triage

Triage begins at the incident itself. The goal is to confirm who was targeted, where the sign-in came from, what the machine detected, and whether the automated verdict can be trusted. Low-severity identity alerts on finance staff are exactly where a patient operator hides, so the machine's rating is a starting point, not a conclusion.

---

### Q01: The Compromised Principal

**Question:** Open the incident. Who is the account this fired on. Full UPN.

**Answer:** `m.smith@lognpacific.org`

**Screenshot**

<!-- ![Q01](screenshots/q01.png) -->

---

### Q02: The Flagged Source

**Question:** Same incident. What address did the flagged sign-in come from.

**Answer:** `103.69.224.136`

**Screenshot**

<!-- ![Q02](screenshots/q02.png) -->

---

### Q03: The Client OS

**Question:** Read the user-agent on that sign-in. What client OS is it.

**Answer:** `Linux`

**Screenshot**

<!-- ![Q03](screenshots/q03.png) -->

---

### Q04: The Stored Detection Type

**Question:** The incident title is the friendly name. Pull the risk telemetry and give me the detection type as it is stored.

**Answer:** `anonymizedIPAddress`

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| project TimeGenerated, RiskEventTypes, RiskEventTypes_V2, RiskLevel, RiskDetail
```

**Screenshot**

<!-- ![Q04](screenshots/q04.png) -->

---

### Q05: Audit the Verdict

**Question:** This user has more than one risk detection. Aggregate them by state and tell me where most of them ended up.

**Answer:** `dismissed`

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where RiskEventTypes contains "anonymizedIPAddress"
| summarize count() by RiskState
```

**Screenshot**

<!-- ![Q05](screenshots/q05.png) -->

---

### Q06: Live Exposure

**Question:** Check the asset record on the incident. What is the account status.

**Answer:** `Enabled`

**Screenshot**

<!-- ![Q06](screenshots/q06.png) -->

**Stage 01 Notes**

- m.smith@lognpacific.org signed in from anonymous IP 103.69.224.136 in Amsterdam on a Linux client: atypical for a finance user
- Entra rated the detection Low and auto-dismissed it without investigation, leaving the account Enabled
- The same IP appeared in linked incident 87236 against a separate user, pointing to shared attacker infrastructure rather than a single targeted compromise
- The Low rating did not reflect the reality: full compromise with no containment taken

---

## Stage 02: Session Scope

Session scope maps the attacker's footprint from first authentication through to every service they touched. The key questions are how they got past the authentication controls, what they accessed once inside, and what identifier threads the sign-in to downstream activity.

---

### Q07: How the Session Beat MFA

**Question:** Tenant enforces MFA. Their session ran anyway. Pull the successful sign-ins from that address and give me the field that explains it.

**Answer:** `singleFactorAuthentication`

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| project TimeGenerated, IPAddress, AuthenticationDetails, AuthenticationRequirement
```

**Screenshot**

<!-- ![Q07](screenshots/q07.png) -->

---

### Q08: The Control Surface That Let Them In

**Question:** Some attempts were stopped, one app let them in. Order the sign-ins from that address and name the app on the first success.

**Answer:** `One Outlook Web`

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| order by TimeGenerated asc
| project TimeGenerated, ResultSignature, AppDisplayName
```

**Screenshot**

<!-- ![Q08](screenshots/q08.png) -->

---

### Q09: Failed Attempts Before Entry

**Question:** Before the session took, the same address failed on credentials. How many times. Bad-password failures only.

**Answer:** `2`

```kql
SigninLogs
| where TimeGenerated < datetime(2026-06-11T03:09:00Z)
| where IPAddress == "103.69.224.136"
| where UserPrincipalName == "m.smith@lognpacific.org"
| where ResultType == 50126
| project TimeGenerated, ResultSignature, ResultDescription, Identity
```

**Screenshot**

<!-- ![Q09](screenshots/q09.png) -->

---

### Q10: Blast Radius of One Token

**Question:** That session reached multiple apps with no re-prompt. Count the distinct apps it got into.

**Answer:** `7`

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where IPAddress == "103.69.224.136"
| where UserPrincipalName == "m.smith@lognpacific.org"
| where ResultSignature == "SUCCESS"
| distinct AppDisplayName
| count
```

**Screenshot**

<!-- ![Q10](screenshots/q10.png) -->

---

### Q11: One Continuous Session

**Question:** I want the sign-in and the later activity tied to one session. Find the identifier that is in both and give it to me.

**Answer:** `005d431a-380b-1f5e-e554-16d5010dc28e`

```kql
SigninLogs
| where IPAddress == "103.69.224.136"
| where UserPrincipalName == "m.smith@lognpacific.org"
| where ResultType == 0
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| project TimeGenerated, SessionId
| order by TimeGenerated asc
```

**Screenshot**

<!-- ![Q11](screenshots/q11.png) -->

**Stage 02 Notes**

- Two bad-password failures at ResultType 50126 before a successful hit at 03:09 UTC via One Outlook Web: minimal spray, not a noisy brute force
- Despite the tenant enforcing MFA, AuthenticationRequirement resolved to singleFactorAuthentication across every successful sign-in, meaning MFA was never challenged
- Every successful sign-in showed authenticationMethod "Previously satisfied": a stolen token with MFA already baked in was replayed with no re-prompt (MITRE T1550.004)
- The token reached 7 distinct apps within the session window
- SessionId 005d431a-380b-1f5e-e554-16d5010dc28e is consistent across all sign-in rows and is the pivot key into downstream tables
- Session end time still unconfirmed: needs cross-referencing against later stage activity

---

## Stage 03: Directory Recon

Before committing to fraud, a patient operator profiles the environment. This stage looks for Graph API calls made during the session that reveal what the attacker was trying to learn: MFA posture, group memberships, org structure: and how that intelligence shaped what came next.

---

### Q12: MFA-Posture Profiling

**Question:** Early in the session there is a Graph reports call profiling this account's auth posture. Name the resource they queried.

**Answer:** `userRegistrationDetails`

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where RequestUri contains "report"
| project TimeGenerated, RequestUri, UserId, ResponseStatusCode
```

**Screenshot**

<!-- ![Q12](screenshots/q12.png) -->

---

### Q13: Group Enumeration

**Question:** There is a Graph call enumerating the victim's own group membership. Give me the request path.

**Answer:** `/v1.0/me/memberOf`

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where SessionId contains "005d431a-380b-1f5e-e554-16d5010dc28e"
| where RequestUri contains "memberof"
| project TimeGenerated, RequestUri, UserId, ResponseStatusCode
```

**Screenshot**

<!-- ![Q13](screenshots/q13.png) -->

**Stage 03 Notes**

- First Graph call hit `/beta/reports/authenticationMethods/userRegistrationDetails` filtered on m.smith with `isMfaCapable eq true`: the attacker was confirming MFA was not registered before acting
- Second call enumerated group memberships via `/v1.0/me/memberOf`, followed by a direct lookup of group ec5fd539-89a9-489b-8b61-ab2c1b8f9386 by ID
- The sequence: MFA check, then group map, then fraud: shows deliberate pre-operation intelligence gathering, not opportunistic browsing
- The recon almost certainly answered whether j.reynolds had the authority to action a payment request from m.smith

---

## Stage 04: The Fraud

The fraud stage reconstructs how the attacker converted mailbox access into a financial attack. This means finding the fraudulent outbound email, identifying the thread they mined to make it credible, confirming who was targeted, and tracing whether the request was pushed through any channel beyond mail.

---

### Q14: The Fraudulent Request

**Question:** From the mailbox they sent an internal email to redirect a payment. Find it. Subject line, exact.

**Answer:** `Updated Banking Details - Pacific IT Monthly`

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where SenderMailFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, DeliveryLocation, EmailDirection, RecipientEmailAddress, Subject
```

**Screenshot**

<

---

### Q15: The Thread They Mined

**Question:** During recon they read an internal thread about the payment-approval process to price the fraud. It predates the intrusion by months. Find that thread and give me its subject line, exact.

**Answer:** `Q1 Vendor Payment Schedule - Review Required`

```kql
EmailEvents
| where TimeGenerated < (datetime(2026-06-11T03:00:00Z))
| where Subject contains "payment"
| where SenderMailFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
| order by TimeGenerated asc
```

**Screenshot**

<!-- ![Q15](screenshots/q15.png) -->

---

### Q16: The Fraud Target

**Question:** Who received the fraudulent request. Full UPN.

**Answer:** `j.reynolds@lognpacific.org`

```kql
EmailEvents
| where TimeGenerated < (datetime(2026-06-11T03:00:00Z))
| where Subject contains "payment"
| where SenderMailFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
| order by TimeGenerated asc
```

**Screenshot**

<!-- ![Q16](screenshots/q16.png) -->

---

### Q17: Second Channel Reinforcement

**Question:** They pushed the same request through a second service, not just mail. Name it.

**Answer:** `Microsoft Teams`

```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where UserId == "m.smith@lognpacific.org"
| project TimeGenerated, OfficeWorkload, RecordType, Operation, UserId
```

**Screenshot**

<!-- ![Q17](screenshots/q17.png) -->

**Stage 04 Notes**

- The attacker read "Q1 Vendor Payment Schedule - Review Required", an internal thread predating the intrusion by months, to extract payment approval context before constructing the fraud
- Fraudulent email sent from m.smith@lognpacific.org to j.reynolds@lognpacific.org with subject "Updated Banking Details - Pacific IT Monthly": specific enough to appear routine for a finance team
- The same request was reinforced via Microsoft Teams: two channels from the same trusted colleague reads as urgency, not suspicion
- The fraud was not improvised: the attacker understood the org's payment workflow before sending a single message

---

## Stage 05: Persistence Hunt

**Context**

| Field | Value |
|---|---|
| Inbox rule name | |
| Rule condition | |
| Rule action | |
| Forwarding address | |
| OAuth app consent | |
| New MFA method added | |
| Other persistence | |

---

### Q18: The Concealment Rule

**Question:**

**Answer:**

```kql

```

**Screenshot**

<!-- ![Q18](screenshots/q18.png) -->

---

### Q19: Where the Hidden Mail Goes

**Question:**

**Answer:**

```kql

```

**Screenshot**

<!-- ![Q19](screenshots/q19.png) -->

---

### Q20: The Exfiltration Rule

**Question:**

**Answer:**

```kql

```

**Screenshot**

<!-- ![Q20](screenshots/q20.png) -->

---

### Q21: Who Both Rules Target

**Question:**

**Answer:**

```kql

```

**Screenshot**

<!-- ![Q21](screenshots/q21.png) -->

---

## Stage 06: Data Theft

**Context**

| Field | Value |
|---|---|
| Files accessed | |
| SharePoint / OneDrive activity | |
| Volume estimate | |
| Exfil method | |
| Destination | |
| Exfil window (UTC) | |

---

### Q22: The Exfil Operation

**Question:**

**Answer:**

```kql

```

**Screenshot**

<!-- ![Q22](screenshots/q22.png) -->

---

### Q23: Volume Taken

**Question:**

**Answer:**

```kql

```

**Screenshot**

<!-- ![Q23](screenshots/q23.png) -->

---

### Q24: The Credential Document

**Question:**

**Answer:**

```kql

```

**Screenshot**

<!-- ![Q24](screenshots/q24.png) -->

---

### Q25: The Vault Pointer

**Question:**

**Answer:**

```kql

```

**Screenshot**

<!-- ![Q25](screenshots/q25.png) -->

---

## Stages 07 and Beyond: Judgement

*Flags Q26 to Q38 to be confirmed as stages are unlocked.*

| # | Title | Points | Answer |
|---|---|---|---|
| Q26 | | | |
| Q27 | | | |
| Q28 | | | |
| Q29 | | | |
| Q30 | | | |
| Q31 | | | |
| Q32 | | | |
| Q33 | | | |
| Q34 | | | |
| Q35 | | | |
| Q36 | | | |
| Q37 | | | |
| Q38 | | | |

---

## Attack Timeline

| Time (UTC) | Stage / Table | Event |
|---|---|---|
| 2026-06-11 03:07 | Stage 02 / SigninLogs | 2 bad-password failures from 103.69.224.136 against m.smith |
| 2026-06-11 03:09 | Stage 02 / SigninLogs | First successful sign-in via One Outlook Web, singleFactorAuthentication |
| 2026-06-11 03:09 to 05:03 | Stage 02 / SigninLogs | Token replayed across 7 apps with no MFA re-prompt |
| | | |
| | | |
| | | |
| | | |
| | | |

---

## IOC Register

| Type | Value | Context |
|---|---|---|
| IP | 103.69.224.136 | Anon sign-in source, Amsterdam NL, linked to incidents 87241 and 87236 |
| UPN | m.smith@lognpacific.org | Compromised finance account |
| Session | 005d431a-380b-1f5e-e554-16d5010dc28e | Attacker session GUID spanning all app access |
| IP | | |
| Domain | | |
| Domain | | |
| Email | | |
| OAuth App | | |

---

## Sign-Off

| | |
|---|---|
| Flags captured | 11 / 38 |
| Hunt duration | |
| Completed | |
| Sign-off | |

---

*// CYBER RANGE // 0x48554E54 // LOG(N) Pacific // Incident 87241*
