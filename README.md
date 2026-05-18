# Windows Threat Detection Lab — Splunk SIEM Project

**Fredrick Ighile** | [github.com/Fredrickighile](https://github.com/Fredrickighile) | [LinkedIn](https://linkedin.com/in/fredrick-ighile)

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Tools and Technologies](#tools-and-technologies)
3. [Lab Architecture](#lab-architecture)
4. [Attack Scenario](#attack-scenario)
5. [Detection 1 — Brute Force Login Attempts](#detection-1--brute-force-login-attempts)
6. [Detection 2 — Successful Login After Brute Force](#detection-2--successful-login-after-brute-force)
7. [Detection 3 — Full Attack Timeline](#detection-3--full-attack-timeline)
8. [Detection 4 — Compromised Host Classifier](#detection-4--compromised-host-classifier)
9. [SOC Dashboard](#soc-dashboard)
10. [Automated Alert](#automated-alert)
11. [Incident Response Runbook](#incident-response-runbook)
12. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
13. [Key Takeaways](#key-takeaways)

---

## Project Overview

This project simulates a real-world brute force attack and demonstrates how a SOC analyst detects, investigates, and responds to it using Splunk SIEM.

The goal was to build something that reflects what security teams actually do day-to-day — ingest logs, write detections, build dashboards, and configure alerts — not just follow a tutorial.

**What was built:**
- A working Splunk SIEM environment ingesting live Windows Event Logs
- A simulated brute force attack with realistic log data
- 4 SPL detection queries mapped to MITRE ATT&CK
- A SOC dashboard showing the full attack picture
- An automated hourly alert that fires when brute force is detected
- A complete incident response runbook

---

## Tools and Technologies

| Tool | Purpose |
|---|---|
| Splunk Enterprise 10.2.2 | SIEM platform — log ingestion, search, alerting |
| Windows Event Logs | Primary data source (Security, System, Application) |
| SPL (Splunk Processing Language) | Detection query language |
| MITRE ATT&CK Framework | Mapping detections to real threat techniques |
| PowerShell | Attack simulation and log generation |
| GitHub | Documentation and portfolio |

---

## Lab Architecture

```
[Windows Host: SOC-LAB-01]
        |
        | Windows Event Logs (Security, System, Application)
        |
[Splunk Enterprise - localhost:8001]
        |
        |--- Index: default
        |--- Source: WinEventLog:Security
        |--- Source: brute_force.log (simulated attack data)
        |
        |--- 4 SPL Detections
        |--- SOC Dashboard
        |--- Automated Alert (hourly)
```

---

## Attack Scenario

**Scenario:** An attacker from a machine named `KALI-ATTACK` attempts to brute force the `administrator` account on a Windows host. After 7 failed attempts across multiple usernames, they successfully authenticate at 12:00:08.

**Accounts targeted:** administrator, admin, guest
**Attack duration:** 8 seconds (12:00:01 — 12:00:08)
**Result:** Administrator account compromised via network logon (Logon Type 3)

**Event IDs used:**

| Event ID | Meaning |
|---|---|
| 4625 | Failed logon attempt |
| 4624 | Successful logon |

---

## Detection 1 — Brute Force Login Attempts

**What it detects:** Any account with more than 3 failed login attempts — the classic brute force signature.

**SPL Query:**
```spl
source="brute_force.log" EventCode=4625
| stats count by Account_Name
| where count > 3
| sort -count
```

**Result:**

| Account_Name | count |
|---|---|
| administrator | 4 |

**Why this matters:** A single failed login is normal. Four or more in a short window from the same source is a strong indicator of a brute force attack. This is one of the most common detections run in Canadian SOC environments.

---

## Detection 2 — Successful Login After Brute Force

**What it detects:** A successful login (Event 4624) following failed attempts — confirming the attacker got in.

**SPL Query:**
```spl
source="brute_force.log" EventCode=4624
| table _time, Account_Name, Workstation_Name, Logon_Type
| sort -_time
```

**Result:**

| Time | Account_Name | Workstation_Name | Logon_Type |
|---|---|---|---|
| 2026-05-17 12:00:08 | administrator | KALI-ATTACK | 3 |

**Why this matters:** This is the moment of confirmed compromise. Logon Type 3 means network logon — the attacker authenticated remotely. This event triggers incident response.

---

## Detection 3 — Full Attack Timeline

**What it detects:** The complete attack story from first attempt to successful breach, with clear labels.

**SPL Query:**
```spl
source="brute_force.log"
| eval Status=if(EventCode=4624,"SUCCESS - ATTACKER GOT IN","FAILED ATTEMPT")
| table _time, Account_Name, Workstation_Name, EventCode, Status
| sort _time
```

**Result:**

| Time | Account | Source | EventCode | Status |
|---|---|---|---|---|
| 12:00:01 | administrator | KALI-ATTACK | 4625 | FAILED ATTEMPT |
| 12:00:02 | administrator | KALI-ATTACK | 4625 | FAILED ATTEMPT |
| 12:00:03 | administrator | KALI-ATTACK | 4625 | FAILED ATTEMPT |
| 12:00:04 | administrator | KALI-ATTACK | 4625 | FAILED ATTEMPT |
| 12:00:05 | admin | KALI-ATTACK | 4625 | FAILED ATTEMPT |
| 12:00:06 | admin | KALI-ATTACK | 4625 | FAILED ATTEMPT |
| 12:00:07 | guest | KALI-ATTACK | 4625 | FAILED ATTEMPT |
| 12:00:08 | administrator | KALI-ATTACK | 4624 | SUCCESS - ATTACKER GOT IN |

---

## Detection 4 — Compromised Host Classifier

**What it detects:** Automatically classifies attacking hosts as COMPROMISED or BLOCKED.

**SPL Query:**
```spl
source="brute_force.log"
| stats count(eval(EventCode=4625)) as Failed_Attempts,
        count(eval(EventCode=4624)) as Successful_Logins
  by Workstation_Name
| eval Attack_Result=if(Successful_Logins>0, "COMPROMISED", "BLOCKED")
| table Workstation_Name, Failed_Attempts, Successful_Logins, Attack_Result
```

**Result:**

| Workstation_Name | Failed_Attempts | Successful_Logins | Attack_Result |
|---|---|---|---|
| KALI-ATTACK | 7 | 1 | COMPROMISED |

---

## SOC Dashboard

The SOC Threat Detection Dashboard combines all 4 detections into a single view.

**Dashboard panels:**
- Compromised Host Classifier (top-level summary)
- Brute Force Login Attempts (per account)
- Full Attack Timeline (second-by-second)
- Successful Login After Brute Force (confirmed compromise)

> Screenshots in the `/screenshots` folder.

---

## Automated Alert

**Alert name:** ALERT - Brute Force Attack Detected
**Type:** Scheduled, runs every hour
**Trigger condition:** Number of results > 0 (any account with 3+ failed logins)
**Action:** Add to Triggered Alerts console

In a production environment this alert would also:
- Send an email to the SOC team
- Create a ticket in ServiceNow or Jira
- Trigger a Slack/Teams notification to the on-call analyst

---

## Incident Response Runbook

When the brute force alert fires, a SOC analyst follows these steps:

**Step 1 — Verify the alert**
Run the brute force SPL query and confirm the account name and source IP. Check if the count is still rising (active attack) or has stopped.

**Step 2 — Check for successful login**
Run Detection 2 to see if any 4624 events came from the same source. If yes — treat as confirmed compromise and escalate immediately.

**Step 3 — Identify the source**
Check `Workstation_Name` and any available IP address. Is it internal or external? Is it a known asset?

**Step 4 — Containment**
- If internal: isolate the host from the network, disable the compromised account
- If external: block the source IP at the firewall, force password reset on targeted accounts

**Step 5 — Eradication**
- Review what the attacker did after logging in (check process creation logs, Event ID 4688)
- Look for persistence mechanisms (new accounts created, scheduled tasks)

**Step 6 — Recovery**
- Re-enable accounts after password reset
- Monitor the affected host for 24-48 hours post-incident

**Step 7 — Documentation**
- Write incident report with full timeline, impact assessment, and lessons learned
- Update detection rules if attacker used a new technique

---

## MITRE ATT&CK Mapping

| Detection | MITRE Technique | Technique ID |
|---|---|---|
| Brute Force Login Attempts | Brute Force: Password Guessing | T1110.001 |
| Successful Login After Brute Force | Valid Accounts | T1078 |
| Full Attack Timeline | Brute Force | T1110 |
| Compromised Host Classifier | Valid Accounts: Local Accounts | T1078.003 |

---

## Key Takeaways

- Splunk's SPL is powerful for correlating events across time — the `eval` and `stats` commands are essential for detection engineering
- Event IDs 4624 and 4625 are among the most important Windows Security events for any SOC analyst to know
- A single detection query is useful, but chaining multiple detections into a dashboard tells a complete incident story
- Automated alerts reduce mean time to detect (MTTD) — without them, an analyst would have to manually search for attacks
- MITRE ATT&CK mapping adds professional context to every detection and is expected in Canadian enterprise environments

---

*Built as part of a cybersecurity portfolio project targeting SOC Analyst and Security Analyst roles in Canada.*
