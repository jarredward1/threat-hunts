# Threat Hunts

![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel-0078D4?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-Defender%20XDR-00B4D8?logo=microsoft)
![Hunts](https://img.shields.io/badge/Hunts%20Completed-2-brightgreen)
![Flags](https://img.shields.io/badge/Flags%20Captured-38%2F38-success)

> **Real ranges. Live telemetry. Adversaries that don't announce themselves.**

A collection of documented threat hunts completed on live cyber range environments. Each hunt covers a real intrusion scenario investigated through cloud telemetry, endpoint data, and identity logs using Microsoft Sentinel and Microsoft Defender XDR. Every writeup includes the full investigation: stage-by-stage flag breakdown, KQL queries, annotated screenshots, attack timeline, and analyst notes.

---

## 🔍 What Is This?

Threat hunting is not alert response. It is the deliberate, hypothesis-driven search for adversary behavior that has already bypassed automated controls. The hunts in this repository are conducted on live ranges where real attacker actions have been staged across cloud services, identity infrastructure, and endpoint telemetry.

Hunts in this repository take two forms depending on the exercise type.

Scored range hunts (like Second Victor) are structured as staged case files with verified flag answers, KQL queries, annotated screenshots, and analyst notes at each stage. Freeform investigations (like the TOR scenario) follow a narrative format: scenario context, steps taken, chronological timeline, and a full response summary, paired with a red-side document showing how the telemetry was generated.

No simulated logs. No fabricated answers. Just real telemetry and the queries that surface it.

---

## ⚔️ Why It Matters

Most detections catch the obvious. What they miss is the patient operator who signs in from a proxied IP, confirms MFA is not registered, reads a payment thread, and automates exfiltration before the shift changes. These hunts exist to build the skill of finding that kind of activity: cloud-native, identity-first, and designed to look like noise.

The writeups are structured so the reasoning is visible at every step. Not just what was found, but what table it came from, what query surfaced it, and why it matters in context. A flag answered without understanding the telemetry is not a finding; it is a guess.

---

## 🛠️ Tools & Telemetry
- **SIEM:** Microsoft Sentinel
- **EDR/XDR:** Microsoft Defender for Endpoint / Defender XDR
- **Query Language:** KQL (Kusto Query Language)
- **Data Sources:** Azure AD sign-in logs, M365 audit logs, endpoint telemetry, Power Automate activity

---

## 📂 Hunts at a Glance

| Hunt | Platform | Scenario | Flags | Status |
|---|---|---|---|---|
| [Second Victor](second-victor.md) | Microsoft Sentinel / Defender XDR | M365 identity compromise, BEC, and silent exfiltration via Power Automate | 38 / 38 | ✅ Complete |
| [TOR Scenario](tor-scenario/) | Microsoft Defender for Endpoint | Unauthorized TOR browser installation and usage on a managed endpoint (freeform investigation + red-side simulation) | N/A | ✅ Complete |
