# Threat Hunt: Second Victor
### M365 Compromise & Business Email Compromise

```
Incident   : 87241
Workspace  : law-cyber-range (Microsoft Sentinel)
Platform   : Microsoft 365 · Entra ID · Defender XDR
Window     : 2026-06-11 03:00 to 13:00 UTC
Flags      : 38 across multiple stages
Difficulty : Intermediate · T2
Hunter     : Jarred Ward
Date       : June 24, 2026
```

---

## Scorecard

| Stage | Flags | Status |
|---|---|---|
| 00 · Incident Handoff | Q00 | ✅ 1 / 1 |
| 01 · Triage | Q01 to Q06 | ✅ 6 / 6 |
| 02 · Session Scope | Q07 to Q11 | ✅ 5 / 5 |
| 03 · Directory Recon | Q12 to Q13 | ✅ 2 / 2 |
| 04 · The Fraud | Q14 to Q17 | ✅ 4 / 4 |
| 05 · Persistence Hunt | Q18 to Q21 | ✅ 4 / 4 |
| 06 · Data Theft | Q22 to Q25 | ✅ 4 / 4 |
| 07 · The Plant and the Trigger | Q26 to Q29 | ✅ 4 / 4 |
| 08 · Correlation and Containment | Q30 to Q37 | ✅ 8 / 8 |
| **Total** | | **✅ 38 / 38** |

---

## Scenario

Overnight, Microsoft Entra ID Protection raised an incident against a finance user. A sign-in from an anonymous IP address, flagged on `m.smith` and rated Low. The night shift triaged it, found nothing they could act on, and left it in the queue. Low-severity identity alerts on finance staff are exactly where a patient operator hides.

This one is cloud. No malware to reverse, no endpoint to image. Everything the attacker did, they did through identity, mail, files and cloud services, and every action left a trace in a different table. You will move across the sign-in logs, the mailbox audit, the Graph activity and the mail events, and tie scattered records back to one session. The detection caught one sign-in. It did not ask what happened next.

**What we do not yet know:**

- Whether the Low rating is right, or whether the machine dismissed a full compromise
- What the operator did once inside, and what they took
- What persisted, and whether it still acts with nobody signed in
- Who else was drawn into the fraud, and how

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

---

## 📋 Stage 00: Incident Handoff
*Acknowledge readiness before touching the workspace.*

### ✅ Q00: Acceptance Gate

**Question:** Acknowledge readiness with the phrase from the IR Brief.

**Answer:** `Tier-2 hunter ready`


<img width="569" height="107" alt="q00" src="https://github.com/user-attachments/assets/175a9904-6ae9-47d3-99d5-596fdbd92fe8" />

---

## 🔍 Stage 01: Triage
*Confirm the principal, the source, the OS, and audit the machine's verdict.*

Triage begins at the incident itself. The goal is to confirm who was targeted, where the sign-in came from, what the machine detected, and whether the automated verdict can be trusted. Low-severity identity alerts on finance staff are exactly where a patient operator hides, so the machine's rating is a starting point, not a conclusion. The Evidence and Response pane in Defender XDR is the first stop before touching the Sentinel workspace.

---

### ✅ Q01: The Compromised Principal

**Question:** Open the incident. Who is the account this fired on. Full UPN.

**Answer:** `m.smith@lognpacific.org`


<img width="905" height="133" alt="q01" src="https://github.com/user-attachments/assets/356c2b44-ccaa-48b1-b4cc-689d322b1159" />

---

### ✅ Q02: The Flagged Source

**Question:** Same incident. What address did the flagged sign-in come from.

**Answer:** `103.69.224.136`


<img width="721" height="105" alt="q02" src="https://github.com/user-attachments/assets/2b1628a8-539a-482a-b05f-36fd88b04525" />

---

### ✅ Q03: The Client OS

**Question:** Read the user-agent on that sign-in. What client OS is it.

**Answer:** `Linux`


<img width="589" height="349" alt="q03" src="https://github.com/user-attachments/assets/7aac039b-1824-4b08-be77-940626000723" />

---

### ✅ Q04: The Stored Detection Type

**Question:** The incident title is the friendly name. Pull the risk telemetry and give me the detection type as it is stored.

**Answer:** `anonymizedIPAddress`

```kql
// Stage 01 · SigninLogs
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| project TimeGenerated, RiskEventTypes, RiskEventTypes_V2, RiskLevel, RiskDetail
```


<img width="625" height="227" alt="q04" src="https://github.com/user-attachments/assets/e634e044-7f41-400b-b946-7415309a62cd" />

---

### ✅ Q05: Audit the Verdict

**Question:** This user has more than one risk detection. Aggregate them by state and tell me where most of them ended up.

**Answer:** `dismissed`

```kql
// Stage 01 · SigninLogs
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where RiskEventTypes contains "anonymizedIPAddress"
| summarize count() by RiskState
```


<img width="293" height="135" alt="q05" src="https://github.com/user-attachments/assets/616baac4-3bd3-4f38-a919-0e76e5df82b3" />

---

### ✅ Q06: Live Exposure

**Question:** Check the asset record on the incident. What is the account status.

**Answer:** `Enabled`


<img width="437" height="83" alt="q06" src="https://github.com/user-attachments/assets/97c4d5c5-af9e-49c0-bedd-74c4851f992e" />

---

> "The machine flagged the sign-in, rated it Low, dismissed its own detections, and left the account Enabled. A finance user on a Linux client from an anonymous Amsterdam IP is not a queue item. It is a confirmed compromise."

**Stage 01 Notes**

- m.smith@lognpacific.org signed in from anonymous IP 103.69.224.136 in Amsterdam on a Linux client: atypical for a finance user
- Entra rated the detection Low and auto-dismissed it without investigation, leaving the account Enabled
- The same IP appeared in linked incident 87236 against a separate user, pointing to shared attacker infrastructure rather than a single targeted compromise
- The Low rating did not reflect the reality: full compromise with no containment taken

---

## 🧭 Stage 02: Session Scope
*Map the attacker's footprint from first auth to every service touched.*

Session scope maps the attacker's footprint from first authentication through to every service they touched. The key questions are how they got past the authentication controls, what they accessed once inside, and what identifier threads the sign-in to downstream activity. A single session can span multiple tables, so finding the common key is what makes the rest of the investigation possible. Everything here is in SigninLogs.

---

### ✅ Q07: How the Session Beat MFA

**Question:** Tenant enforces MFA. Their session ran anyway. Pull the successful sign-ins from that address and give me the field that explains it.

**Answer:** `singleFactorAuthentication`

```kql
// Stage 02 · SigninLogs
SigninLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| project TimeGenerated, IPAddress, AuthenticationDetails, AuthenticationRequirement
```


<img width="808" height="130" alt="q07" src="https://github.com/user-attachments/assets/40fc9a22-2789-46e9-ac68-538dee617bd8" />

---

### ✅ Q08: The Control Surface That Let Them In

**Question:** Some attempts were stopped, one app let them in. Order the sign-ins from that address and name the app on the first success.

**Answer:** `One Outlook Web`

```kql
// Stage 02 · SigninLogs
SigninLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| order by TimeGenerated asc
| project TimeGenerated, ResultSignature, AppDisplayName
```


<img width="559" height="118" alt="q08" src="https://github.com/user-attachments/assets/28db8d16-1644-4fad-8a29-2f702038ed06" />

---

### ✅ Q09: Failed Attempts Before Entry

**Question:** Before the session took, the same address failed on credentials. How many times. Bad-password failures only.

**Answer:** `2`

```kql
// Stage 02 · SigninLogs
SigninLogs
| where TimeGenerated < datetime(2026-06-11T03:09:00Z)
| where IPAddress == "103.69.224.136"
| where UserPrincipalName == "m.smith@lognpacific.org"
| where ResultType == 50126
| project TimeGenerated, ResultSignature, ResultDescription, Identity
```


<img width="714" height="134" alt="q09" src="https://github.com/user-attachments/assets/2e248165-8e43-4d17-a4ff-a8e81a14f70b" />

---

### ✅ Q10: Blast Radius of One Token

**Question:** That session reached multiple apps with no re-prompt. Count the distinct apps it got into.

**Answer:** `7`

```kql
// Stage 02 · SigninLogs
SigninLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where IPAddress == "103.69.224.136"
| where UserPrincipalName == "m.smith@lognpacific.org"
| where ResultSignature == "SUCCESS"
| distinct AppDisplayName
| count
```


<img width="304" height="134" alt="q10" src="https://github.com/user-attachments/assets/32a4eab5-d5da-485a-a4a1-4b8fca810a8b" />

---

### ✅ Q11: One Continuous Session

**Question:** I want the sign-in and the later activity tied to one session. Find the identifier that is in both and give it to me.

**Answer:** `005d431a-380b-1f5e-e554-16d5010dc28e`

```kql
// Stage 02 · SigninLogs
SigninLogs
| where IPAddress == "103.69.224.136"
| where UserPrincipalName == "m.smith@lognpacific.org"
| where ResultType == 0
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| project TimeGenerated, SessionId
| order by TimeGenerated asc
```


<img width="876" height="131" alt="q11" src="https://github.com/user-attachments/assets/ea35c32d-0320-49fd-8237-8e757c635735" />

---

> "Two failed attempts, then a hit. MFA never fired. One token, seven apps, no re-prompt. The attacker was inside the tenant for two hours and everything they did looked like routine browser activity."

**Stage 02 Notes**

- Two bad-password failures at ResultType 50126 before a successful hit at 03:09 UTC via One Outlook Web: minimal spray, not a noisy brute force
- Despite the tenant enforcing MFA, AuthenticationRequirement resolved to singleFactorAuthentication across every successful sign-in, meaning MFA was never challenged
- Every successful sign-in showed authenticationMethod "Previously satisfied": a stolen token with MFA already baked in was replayed with no re-prompt (MITRE T1550.004)
- The token reached 7 distinct apps within the session window
- SessionId 005d431a-380b-1f5e-e554-16d5010dc28e is consistent across all sign-in rows and is the pivot key into downstream tables
- Session end time still unconfirmed: needs cross-referencing against later stage activity

---

## 🔬 Stage 03: Directory Recon
*Follow the Graph API calls to understand what the attacker needed to know before acting.*

Before committing to fraud, a patient operator profiles the environment. This stage looks for Graph API calls made during the session that reveal what the attacker was trying to learn: MFA posture, group memberships, and org structure. Understanding what the attacker queried tells you what they needed to know before acting, and why they were confident the fraud would work. The evidence lives in MicrosoftGraphActivityLogs, pivoting on the session identifier confirmed in Stage 02.

---

### ✅ Q12: MFA-Posture Profiling

**Question:** Early in the session there is a Graph reports call profiling this account's auth posture. Name the resource they queried.

**Answer:** `userRegistrationDetails`

```kql
// Stage 03 · MicrosoftGraphActivityLogs
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where RequestUri contains "report"
| project TimeGenerated, RequestUri, UserId, ResponseStatusCode
```


<img width="1294" height="131" alt="q12" src="https://github.com/user-attachments/assets/aa0a8277-a14e-4ecc-8135-93abf139a8e7" />

---

### ✅ Q13: Group Enumeration

**Question:** There is a Graph call enumerating the victim's own group membership. Give me the request path.

**Answer:** `/v1.0/me/memberOf`

```kql
// Stage 03 · MicrosoftGraphActivityLogs
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where SessionId contains "005d431a-380b-1f5e-e554-16d5010dc28e"
| where RequestUri contains "memberof"
| project TimeGenerated, RequestUri, UserId, ResponseStatusCode
```


<img width="510" height="100" alt="q13" src="https://github.com/user-attachments/assets/d3c0a460-b23b-494d-9365-376988ea2250" />

---

> "Before sending a single fraudulent message, the attacker confirmed MFA was not registered and mapped the victim's group memberships. This was not opportunistic. They checked whether the fraud would work before attempting it."

**Stage 03 Notes**

- First Graph call hit `/beta/reports/authenticationMethods/userRegistrationDetails` filtered on m.smith with `isMfaCapable eq true`: the attacker was confirming MFA was not registered before acting
- Second call enumerated group memberships via `/v1.0/me/memberOf`, followed by a direct lookup of group ec5fd539-89a9-489b-8b61-ab2c1b8f9386 by ID
- The sequence: MFA check, then group map, then fraud: shows deliberate pre-operation intelligence gathering, not opportunistic browsing
- The recon almost certainly answered whether j.reynolds had the authority to action a payment request from m.smith

---

## 💸 Stage 04: The Fraud
*Reconstruct the fraud chain from mailbox recon to dual-channel delivery.*

The fraud stage reconstructs how the attacker converted mailbox access into a financial attack. This means finding the fraudulent outbound email, identifying the thread they mined to make it credible, confirming who was targeted, and tracing whether the request was pushed through any channel beyond mail. BEC attacks succeed because they exploit trust: the target receives a request from a known colleague, in a familiar context, using the right language. The goal here is to document the full chain from recon to delivery.

---

### ✅ Q14: The Fraudulent Request

**Question:** From the mailbox they sent an internal email to redirect a payment. Find it. Subject line, exact.

**Answer:** `Updated Banking Details - Pacific IT Monthly`

```kql
// Stage 04 · EmailEvents
EmailEvents
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where SenderMailFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, DeliveryLocation, EmailDirection, RecipientEmailAddress, Subject
```


<img width="1117" height="126" alt="q14" src="https://github.com/user-attachments/assets/5015d1bb-1ee4-430d-9fdf-5b33b9bb18ca" />

---

### ✅ Q15: The Thread They Mined

**Question:** During recon they read an internal thread about the payment-approval process to price the fraud. It predates the intrusion by months. Find that thread and give me its subject line, exact.

**Answer:** `Q1 Vendor Payment Schedule - Review Required`

```kql
// Stage 04 · EmailEvents
EmailEvents
| where TimeGenerated < (datetime(2026-06-11T03:00:00Z))
| where Subject contains "payment"
| where SenderMailFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
| order by TimeGenerated asc
```


<img width="927" height="190" alt="q15" src="https://github.com/user-attachments/assets/9118fc7b-79bc-4def-9bfc-30c79ebcddd2" />

---

### ✅ Q16: The Fraud Target

**Question:** Who received the fraudulent request. Full UPN.

**Answer:** `j.reynolds@lognpacific.org`

```kql
// Stage 04 · EmailEvents
EmailEvents
| where TimeGenerated < (datetime(2026-06-11T03:00:00Z))
| where Subject contains "payment"
| where SenderMailFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
| order by TimeGenerated asc
```


<img width="927" height="190" alt="q16" src="https://github.com/user-attachments/assets/284d3f36-916a-4062-91e7-94e0e787b49a" />

---

### ✅ Q17: Second Channel Reinforcement

**Question:** They pushed the same request through a second service, not just mail. Name it.

**Answer:** `Microsoft Teams`

```kql
// Stage 04 · OfficeActivity
OfficeActivity
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where UserId == "m.smith@lognpacific.org"
| project TimeGenerated, OfficeWorkload, RecordType, Operation, UserId
```


<img width="927" height="161" alt="q17" src="https://github.com/user-attachments/assets/fe5cbcc7-5d33-48da-bdbf-96a04f88c230" />

---

> "The attacker read a months-old payment thread, used the language and context to construct a credible request, then sent it through both email and Teams. Two channels from a trusted colleague reads as urgency. This was not improvised."

**Stage 04 Notes**

- The attacker read "Q1 Vendor Payment Schedule - Review Required", an internal thread predating the intrusion by months, to extract payment approval context before constructing the fraud
- Fraudulent email sent from m.smith@lognpacific.org to j.reynolds@lognpacific.org with subject "Updated Banking Details - Pacific IT Monthly": specific enough to appear routine for a finance team
- The same request was reinforced via Microsoft Teams: two channels from the same trusted colleague reads as urgency, not suspicion
- The fraud was not improvised: the attacker understood the org's payment workflow before sending a single message

---

## 🪤 Stage 05: Persistence Hunt
*Hunt the mechanisms left behind to act with nobody signed in.*

Persistence is what separates a one-time intrusion from a long-term presence. This stage hunts for mechanisms the attacker left behind to maintain access or suppress evidence after the session ends. Inbox rules are the most common cloud persistence technique: they operate silently, survive password resets, and can forward or hide mail with no further attacker involvement. The goal is to find everything that still acts even when nobody is signed in.

---

### ✅ Q18: The Concealment Rule

**Question:** They changed something on the mailbox so a conversation wouldn't be seen. Find the rule and give me its name.

**Answer:** `Invoice Processing`

```kql
// Stage 05 · OfficeActivity
OfficeActivity
| where TimeGenerated < datetime(2026-06-11T13:00:00Z)
| where UserId == "m.smith@lognpacific.org"
| where Operation contains "rule"
| project TimeGenerated, Operation, Parameters
```


<img width="536" height="424" alt="q18" src="https://github.com/user-attachments/assets/2bff0ac4-a099-40e0-8e9c-bda83b21bda2" />

---

### ✅ Q19: Where the Hidden Mail Goes

**Question:** That rule doesn't delete the mail it catches, it moves it to a normal-looking folder. Tell me why an attacker moves instead of deletes, and what the choice of an ordinary folder buys them.

**Answer:** `avoid detection`

---

### ✅ Q20: The Exfiltration Rule

**Question:** There is a second rule that sends mail outside the org. Give me the destination address.

**Answer:** `merovingian1337@proton.me`

```kql
// Stage 05 · OfficeActivity
OfficeActivity
| where TimeGenerated < datetime(2026-06-11T13:00:00Z)
| where UserId == "m.smith@lognpacific.org"
| where Operation contains "rule"
| project TimeGenerated, Operation, Parameters
```


<img width="536" height="362" alt="q20" src="https://github.com/user-attachments/assets/118d67f4-1610-46b7-89d6-e2a48616545d" />

---

### ✅ Q21: Who Both Rules Target

**Question:** Both mailbox rules act on inbound mail from one person. Tell me why the persistence rules single out their mail specifically. What conversation are the rules built to stop the victim from seeing.

**Answer:** `fraud reply`

---

> "Two rules, one target. Invoice Processing archives the reply so m.smith never sees it. Backup Copy forwards it to ProtonMail so the attacker does. Both fire silently after the session ends. The inbox stays clean. The attacker stays informed."

**Stage 05 Notes**

- Two inbox rules created: "Invoice Processing" moves mail from j.reynolds to Archive, "Backup Copy" forwards it externally to merovingian1337@proton.me
- Both rules filter on mail from j.reynolds@lognpacific.org specifically: the fraud target whose reply would expose the attack
- Moving to Archive rather than deleting avoids triggering deletion alerts and looks like normal filing behaviour
- The external forwarding address uses ProtonMail, an encrypted provider that makes interception harder to action
- These rules persist after the attacker's session ends and would continue operating silently through any future sign-in by m.smith

---

## 📤 Stage 06: Data Theft
*Identify what was taken, how many files, and what the selection reveals about intent.*

Data theft is the final objective of the intrusion. This stage identifies what files the attacker took, how many, and what the selection tells you about intent. A small number of specific files points to targeted theft rather than bulk exfiltration. The evidence lives in CloudAppEvents, filtering on FileDownloaded and FileAccessed operations from the attacker's IP.

---

### ✅ Q22: The Exfil Operation

**Question:** One operation in the attacker's session is them taking copies out, not reading in place. Name that operation, and tell me how you separated it from the user's ordinary file activity.

**Answer:** `FileDownloaded, 3 files copied out via attacker IP 103.69.224.136`

```kql
// Stage 06 · CloudAppEvents
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where ActionType contains "download"
| project TimeGenerated, ActionType, ObjectName, ObjectType, IPAddress
```


<img width="978" height="168" alt="q22" src="https://github.com/user-attachments/assets/d664e74d-8428-4366-8bbf-b214a2fc369a" />

---

### ✅ Q23: Volume Taken

**Question:** Count the files they pulled in the session. Then tell me what that number says about the theft: was this someone grabbing whatever they could reach, or a deliberate pull of specific things.

**Answer:** `3, deliberate pull of specific things`

```kql
// Stage 06 · CloudAppEvents
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where ActionType contains "download"
| project TimeGenerated, ActionType, ObjectName, ObjectType, IPAddress
```


<img width="978" height="168" alt="q23" src="https://github.com/user-attachments/assets/650cc139-26bc-4029-a02a-628f9067c1eb" />

---

### ✅ Q24: The Credential Document

**Question:** One of those files widens this past the mailbox. Name it.

**Answer:** `VPN-Access-Credentials.txt`

```kql
// Stage 06 · CloudAppEvents
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where ActionType contains "download"
| project TimeGenerated, ActionType, ObjectName, ObjectType, IPAddress
```


<img width="978" height="168" alt="q24" src="https://github.com/user-attachments/assets/947e0f5f-8709-4f16-9514-766216e9c6e7" />

---

### ✅ Q25: The Vault Pointer

**Question:** They opened a file that points to a credential store, didn't download it. Look at access. Name the file.

**Answer:** `Yomark.pdf`

```kql
// Stage 06 · CloudAppEvents
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where IPAddress contains "103.69.224.136"
| where ObjectType == "File"
| project TimeGenerated, ActionType, ObjectName, ObjectType, IPAddress
```


<img width="1019" height="159" alt="q25" src="https://github.com/user-attachments/assets/14a1d0d0-10d3-4dcc-bb7d-e509cc2180bb" />

---

> "Three files in 90 seconds: a financial ledger, the real vendor banking details, and VPN credentials. Each one has a purpose. Nothing was grabbed at random. The attacker knew exactly where to look."

**Stage 06 Notes**

- Three files downloaded at 03:37 UTC: `Book.xlsx`, `Vendor-Banking-Details.txt`, and `VPN-Access-Credentials.txt`, all from attacker IP 103.69.224.136
- `Vendor-Banking-Details.txt` directly supports the fraud: the attacker likely read the real banking details before substituting their own
- `VPN-Access-Credentials.txt` widens the compromise beyond the mailbox and suggests the attacker is positioning for persistent network access
- `Yomark.pdf` was accessed but not downloaded: opened in place, likely a credential store index or password reference document
- Session end time is approximately 05:08 UTC based on the last FileAccessed events visible in CloudAppEvents

---

## ⚙️ Stage 07: The Plant and the Trigger
*Prove that automated activity continued after the attacker signed out.*

Persistence mechanisms that act without a live session are the hardest to detect and the most dangerous to leave in place. This stage focuses on proving that automated activity continued after the attacker signed out, identifying what triggered it, and building the sequence that disproves any innocent explanation for what happened.

---

### ✅ Q26: Disprove the Innocent Explanation

**Question:** Call's coming in that this is just the user on a VPN. Read the authentication detail across the session and count how many times MFA was actually satisfied.

**Answer:** `0`

```kql
// Stage 07 · SigninLogs
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where ResultType == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| count
```


<img width="298" height="104" alt="q26" src="https://github.com/user-attachments/assets/f6429d4c-2b89-4f5e-aceb-da370733ea68" />

---

### ✅ Q27: Catch the Plant

**Question:** Walk the apps that session touched. One of them is where automation gets built, not where a finance user works. Name it.

**Answer:** `Microsoft Flow Portal`

```kql
// Stage 07 · SigninLogs
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| distinct AppDisplayName
```


<img width="379" height="305" alt="q27" src="https://github.com/user-attachments/assets/284116d5-2317-4da6-ab8d-374941b17599" />

---

### ✅ Q28: The Cause Behind the Forward

**Question:** The forward is in the mail logs. No rule made it, user wasn't online. Find the table that records what actually fired it.

**Answer:** `MicrosoftGraphActivityLogs`


<img width="587" height="50" alt="q28" src="https://github.com/user-attachments/assets/7fa6f6d1-d00e-4a53-909b-dc49e34df987" />

---

### ✅ Q29: Prove It With the Sequence

**Question:** That forward is recorded twice, an API call and a mail event. Put them in order and tell me which came first.

**Answer:** `The graph call`

```kql
// Stage 07 · MicrosoftGraphActivityLogs
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where RequestUri contains "forward" or RequestUri contains "mail"
| project TimeGenerated, RequestUri
| order by TimeGenerated asc

// Stage 07 · EmailEvents
EmailEvents
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where SenderFromAddress == "m.smith@lognpacific.org" or RecipientEmailAddress == "merovingian1337@proton.me"
| project TimeGenerated, Subject, SenderFromAddress, RecipientEmailAddress
| order by TimeGenerated asc
```


<img width="679" height="133" alt="q29a" src="https://github.com/user-attachments/assets/c58d95e5-d58e-4f95-b02e-8ff13743463d" />
<img width="637" height="133" alt="q29b" src="https://github.com/user-attachments/assets/8354109f-0159-4507-ba63-aea7ca521615" />

---

> "The Graph API call fired at 12:41 UTC. The mail event appeared afterward. No user was signed in. Power Automate executed the forward autonomously, proving the attacker built persistence that outlasted their session."

**Stage 07 Notes**

- MFA was satisfied 0 times across the entire session, directly disproving the "user on a VPN" explanation: a legitimate user authenticating via VPN would still satisfy MFA
- Microsoft Flow Portal appearing in a finance user's session is the plant: Power Automate is a developer/automation tool with no legitimate use case for m.smith
- The forward fired via a Graph API call, not an inbox rule, and not by a live user session: this is the automation built in Flow
- The Graph call preceded the mail event, confirming the flow executed the forward programmatically before it appeared in the mail logs

---

## 🔒 Stage 08: Correlation and Containment
*Tie every thread back to one actor and sequence the response correctly.*

Correlation ties every thread of the investigation back to one actor and one infrastructure. Containment orders the response so that the most dangerous footholds are closed first. This stage asks you to prove attribution across all sources, sequence the remediation steps correctly, and identify the control failures that let this happen.

---

### ✅ Q30: The Automation Source IP

**Question:** That forward didn't come from the attacker's address or the user's machine. Where did it come from. Give me the IP.

**Answer:** `20.150.129.194`

```kql
// Stage 08 · MicrosoftGraphActivityLogs
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where RequestUri contains "forward"
```


<img width="356" height="133" alt="q30" src="https://github.com/user-attachments/assets/2d966875-5f66-4724-a335-d533b1d431f9" />

---

### ✅ Q31: The Automation Identity

**Question:** The forward call is signed by an app. Give me the app id off that record.

**Answer:** `7ab7862c-4c57-491e-8a45-d52a7e023983`

```kql
// Stage 08 · MicrosoftGraphActivityLogs
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where RequestUri contains "forward"
| project TimeGenerated, RequestUri, AppId
```


<img width="685" height="109" alt="q31" src="https://github.com/user-attachments/assets/5e7545d0-15e5-4029-b767-fbde11490b42" />

---

### ✅ Q32: Name the Abused Service

**Question:** The app they signed into, the call that fired, the app id behind it. Name the service they used to forward the mail.

**Answer:** `Power Automate`

```kql
// Stage 08 · MicrosoftGraphActivityLogs
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where AppId == "7ab7862c-4c57-491e-8a45-d52a7e023983"
| project TimeGenerated, AppId, UserAgent
```


<img width="1174" height="131" alt="q32" src="https://github.com/user-attachments/assets/aa17cb0a-5fc2-4d5b-9fa9-44e8ac27dd54" />

---

### ✅ Q33: One Actor, Every Source

**Question:** One address runs through the whole case. Count how many distinct log sources it appears in. Window: 10 to 20 June 2026 UTC. Scope: in-scope tables from the data dictionary only, where the IP literally appears in a field.

**Answer:** `7`

*AuditLogs is the only in-scope table with no IP address field containing the attacker IP.*

```kql
// Stage 08 · Run individually per table, count those returning > 0
SigninLogs
| where TimeGenerated between (datetime(2026-06-10T00:00:00Z) .. datetime(2026-06-20T23:59:59Z))
| where IPAddress == "103.69.224.136"
| count
```

---

### ✅ Q34: Containment Ordering

**Question:** Before you delete a rule or a flow, one action comes first or they're straight back in. What is it.

**Answer:** `revoke session`

---

### ✅ Q35: Where the Flow Is Removed

**Question:** That flow can't be removed from Sentinel or the Exchange rules. Where do you go to find and delete it.

**Answer:** `Power Platform admin center`

---

### ✅ Q36: The Control That Never Fired

**Question:** A foreign single-factor sign-in should have been the easiest thing in the world for Conditional Access to stop. Check what Conditional Access actually did on these sign-ins, then tell me what you found and why that's how the session got through.

**Answer:** `notApplied, legacy client not covered by policy`

```kql
// Stage 08 · SigninLogs
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where ResultType == 0
| project TimeGenerated, ConditionalAccessStatus, ClientAppUsed, AuthenticationRequirement
```


<img width="712" height="129" alt="q36" src="https://github.com/user-attachments/assets/10436533-212b-4103-853c-edd92e01258f" />

---

### ✅ Q37: Why Revoke Before Reset

**Question:** Someone wants to reset m.smith's password and call it done. Tell me why a password reset alone doesn't lock this attacker out, and what action has to come first.

**Answer:** `session token survives, revoke access`

---

> "A password reset changes the credential. It does not kill the session. The stolen token remains valid until explicitly revoked, meaning the attacker stays inside the tenant while the defender thinks the lock has been changed."

**Stage 08 Notes**

- The forward fired from 20.150.129.194, an Azure infrastructure IP, not the attacker's known address: confirming automation ran independently of the live session
- AppId 7ab7862c-4c57-491e-8a45-d52a7e023983 maps to Power Automate (formerly Microsoft Flow), confirmed by the UserAgent string containing `microsoft-flow/1.0`
- The attacker IP appeared in 7 of 8 in-scope tables: AuditLogs is the only one with no IP address field containing 103.69.224.136
- CA was never invoked because the legacy browser client path fell outside the scope of any CA policy: ConditionalAccessStatus shows notApplied across every sign-in
- A password reset alone does not contain this compromise: the stolen session token remains valid until explicitly revoked, meaning the attacker retains access even after a credential change

---

## Attack Timeline

| Time (UTC) | Table | Event |
|---|---|---|
| 2026-06-11 03:07 | SigninLogs | 2 bad-password failures from 103.69.224.136 against m.smith |
| 2026-06-11 03:09 | SigninLogs | First successful sign-in via One Outlook Web, singleFactorAuthentication |
| 2026-06-11 03:09 | MicrosoftGraphActivityLogs | Graph API call to userRegistrationDetails to confirm MFA not registered |
| 2026-06-11 03:09 | MicrosoftGraphActivityLogs | Graph API call to /v1.0/me/memberOf to enumerate group memberships |
| 2026-06-11 03:13 | SigninLogs | Token replayed across 7 apps with no MFA re-prompt |
| 2026-06-11 03:13 | OfficeActivity / EmailEvents | Mailbox recon: MailItemsAccessed events, thread "Q1 Vendor Payment Schedule - Review Required" read |
| 2026-06-11 03:28 | OfficeActivity | Inbox rule "Invoice Processing" created: moves j.reynolds mail to Archive |
| 2026-06-11 03:32 | OfficeActivity | Inbox rule "Backup Copy" created: forwards j.reynolds mail to merovingian1337@proton.me |
| 2026-06-11 03:37 | CloudAppEvents | 3 files downloaded: Book.xlsx, Vendor-Banking-Details.txt, VPN-Access-Credentials.txt |
| 2026-06-11 03:39 | CloudAppEvents | Yomark.pdf accessed (not downloaded) |
| 2026-06-11 04:13 | EmailEvents | Fraudulent email sent to j.reynolds: "Updated Banking Details - Pacific IT Monthly" |
| 2026-06-11 05:08 | CloudAppEvents | Last confirmed attacker activity |
| 2026-06-11 12:41 | MicrosoftGraphActivityLogs | Power Automate flow fires forward from 20.150.129.194 with no live session |

---

## IOC Register

| Type | Value | Context |
|---|---|---|
| IP | 103.69.224.136 | Anon sign-in source, Amsterdam NL, linked to incidents 87241 and 87236 |
| IP | 20.150.129.194 | Azure Power Automate infrastructure IP that fired the external forward |
| UPN | m.smith@lognpacific.org | Compromised finance account (Mark Smith) |
| Session | 005d431a-380b-1f5e-e554-16d5010dc28e | Attacker session GUID spanning all app access |
| App ID | 7ab7862c-4c57-491e-8a45-d52a7e023983 | Power Automate app ID used to sign and fire the forwarding flow |
| Email | merovingian1337@proton.me | External forwarding destination for Backup Copy inbox rule |
| UPN | j.reynolds@lognpacific.org | Fraud target: recipient of fraudulent payment redirect email |
| File | VPN-Access-Credentials.txt | Downloaded credential document from IT-Credentials folder |
| File | Vendor-Banking-Details.txt | Downloaded file from Finance folder, directly supports fraud |
| File | Yomark.pdf | Accessed credential store pointer, not downloaded |
| Inbox Rule | Invoice Processing | Moves j.reynolds mail to Archive to conceal fraud reply |
| Inbox Rule | Backup Copy | Forwards j.reynolds mail to merovingian1337@proton.me |

---

## Sign-Off

```
HUNT     : Second Victor
ANALYST  : Jarred Ward
SCORE    : 38 / 38
DATE     : June 24, 2026
STATUS   : Complete
```

---
