# OT Incident Response Runbook

> Repo path: `soar/docs/ot-ir-runbook.md`
> Satisfies **DoW ZT for OT activity 6.7.1** (documented OT-specific incident response process) and incorporates the controlled-recovery requirement of **7.2.1**. It is the prose companion to `decision-matrix.md`, the watchlists, and the playbooks.

## 1. Purpose and scope

This runbook defines how security incidents in the OT monitoring lab are triaged, decided, contained, and recovered. It covers the synthetic OT environment fed by `ot_log_generator.py` (Dragos Platform, Forescout eyeInspect, Forescout eyeSegment) into Microsoft Sentinel, the six detections in `detections/`, and the SOAR layer in `soar/`. It is written to mirror a real OT process so the approach transfers beyond the lab, and it aligns to the Detect, Mitigate, Recover model from the ACI TTP for DoW ICS referenced in the Zero Trust for OT guidance.

## 2. Guiding principles

OT incident response inverts the usual IT priority order. Availability and safety of the physical process come before confidentiality, so the process is built on three rules:

1. Safety, process reliability, and mission take precedence over speed of containment.
2. Any response that touches a live process or an OT control path requires a human decision; it is never automated.
3. Reconnection after containment is deliberate and validated, never automatic.

These rules are enforced in tooling, not just stated here: the tiering in the decision matrix, the safety floor in the watchlists, and the approval gate in the containment playbook.

## 3. Roles and responsibilities

| Role | Responsibility |
|---|---|
| SOC analyst | Monitors incidents, confirms the automated enrichment, handles Tier 0 work, escalates Tier 1 and Tier 2. |
| OT engineer (Controls Engineering) | Authority on process impact for their plant. Approves or rejects proposed containment and leads recovery. |
| Asset owner / POC | Named in `ot-subnet-context.poc_contact`. Receives the approval request and makes the gated decision. |
| Safety Systems team | Owns safety controllers (SIS). Handles any safety-controller event manually and coordinated. |
| Incident lead | Coordinates communication and timeline for high-severity incidents. |

## 4. Pipeline overview

A detection fires in Sentinel and creates an incident. A single automation rule then runs the enrichment playbook followed by the gated-containment playbook. Enrichment performs the asset lookups, computes the effective response tier, and writes context, severity, and a `tier-N` tag onto the incident. Containment runs only for `tier-2` incidents and only acts on human approval. Everything else is analyst-driven from the enriched incident.

```
Detection (KQL analytics rule)
   -> Sentinel incident (DestinationIP mapped as IP entity)
      -> Automation rule
         -> Enrichment & triage playbook   (subnet + role lookups, effective tier, severity, tags)
         -> Approval-gated containment      (tier-2 only; proposes, waits for approval, records recovery)
```

## 5. Response tiers

The tiers come from `decision-matrix.md` and are computed as `max(detection default, asset rule floor)`.

- **Tier 0, observe and enrich.** Automated context, severity, tagging, and notification. No containment. Analyst investigates.
- **Tier 1, conditional IT-side containment.** Automated containment only when the affected asset is IT-side and non-critical. Escalates to Tier 2 otherwise.
- **Tier 2, approval-gated OT containment.** Containment is proposed and executed only on human approval, followed by controlled recovery.

## 6. Lifecycle

### Detect
A KQL analytics rule matches Dragos or Forescout telemetry and raises an alert and incident. Each rule maps `DestinationIP` as the IP entity so the affected asset is unambiguous.

### Triage and enrich (automated)
The enrichment playbook resolves the affected asset to its subnet context (zone, plant, Purdue level, owner, contact, maintenance window) and role context (device class, criticality), sets the effective tier and severity, and tags the incident. The SOC analyst reads the enriched incident rather than starting from raw logs.

### Decide
Tier 0 stays with the analyst. Tier 1 may auto-contain on the IT side. Tier 2 moves to the approval gate. A safety-controller event always goes to the Safety Systems team regardless of other factors.

### Contain (gated for Tier 2)
The containment playbook proposes a device-appropriate action and routes it to the asset POC for approval. On approval the action is taken (simulated in the lab) and the incident is tagged `contained-sim` and `pending-controlled-recovery`. On rejection the incident is left active for manual handling.

### Recover (controlled, activity 7.2.1)
Reconnection follows the controlled-recovery checklist in section 7. The incident is not closed until recovery is validated.

### Close and improve
The analyst documents the outcome, confirms recovery, and records any tuning needed (for example a false positive that should be suppressed during a maintenance window). Closed incidents feed detection and watchlist improvements.

## 7. Controlled recovery checklist (activity 7.2.1)

1. Confirm the process is in a safe state with the OT engineer before any reconnection.
2. Confirm the root cause is understood and the offending activity has stopped.
3. Restore connectivity in a controlled, monitored window.
4. Validate device state and process variables after reconnection.
5. Document the recovery and close the incident only after validation.

## 8. Per-detection response cards

| Detection | Tier | Notify | Action |
|---|---|---|---|
| WorldView IOC match (01) | 1, escalates to 2 | SOC, then OT engineer if OT asset | Auto-isolate only if IT-side; gate if OT controller or HMI. |
| PLC program download (02) | 2 | OT engineer / Controls | Check maintenance window first; gate isolation; verify with engineering. |
| PLC mode change to PROGRAM (03) | 2 | OT engineer / Controls, urgent | Treat as process-stopping; immediate page; gated containment with controlled recovery. |
| Safety controller write (04) | 2 forced | Safety Systems, urgent | No automated isolation even with approval; manual coordinated handling. |
| Segmentation policy blocked (05) | 0, conditional 1 | SOC | Already blocked by eyeSegment; investigate the attempt; consider IT-side block if OT-to-Internet. |
| Cross-platform correlation (06) | inherits, default 2 | OT engineer / Controls | High-confidence; raise severity; gate containment on the correlated OT asset. |

## 9. Communication and escalation

Approval requests route automatically to the asset POC from the watchlist. For high-severity or safety-related incidents, the incident lead coordinates a bridge with the OT engineer and, for SIS events, the Safety Systems team. Use the incident comments as the single source of timeline and decisions so the record stays with the incident.

## 10. False positives and maintenance windows

Program-download and mode-change detections are expected during scheduled maintenance. The `maintenance_window` field in `ot-subnet-context` documents those windows; suppress or downgrade matching events during them, and record any tuning in the closed incident so the analytics rule or watchlist can be adjusted.

## 11. Mapping to DoW ZT for OT activities

| Element | Activity |
|---|---|
| This runbook (documented OT IR process) | 6.7.1 |
| Tiering and response analysis | 6.5.1 |
| Playbooks that execute the process | 6.5.2 |
| Asset-ID-driven enrichment and routing | 7.2.5 |
| Gated isolation and controlled recovery | 7.2.1 |
| Advanced and enriched response | 6.7.2 |

## 12. Assumptions and lab limitations

- Telemetry is synthetic and containment is simulated. The decision flow, documentation, and recovery process are the deliverable.
- Because the generator places affected assets only in plant subnets (Purdue 1 and 2), Tier 2 dominates in practice; the Tier 1 auto-containment branch is exercised only if the generator is extended to emit IT-side destinations.
- Connector action shapes in the playbooks may vary by version; the logic and process are authoritative, the exact action wiring is environment-specific.
