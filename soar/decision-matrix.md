# OT Response-Automation Decision Matrix

> Repo path: `soar/decision-matrix.md`
> Satisfies **DoW ZT for OT activity 6.5.1: OT Response Automation Analysis**, and feeds 6.5.2 (SOAR tooling), 6.7.1 (IR guidance), and 7.2.5 outcome 3 (asset-ID-driven automated response).

## Purpose

This matrix classifies each v1 detection by **how much of its response can be safely automated** in an OT environment. It is the control document for the SOAR layer: every playbook reads its behavior from here, and nothing gets automated that isn't justified below.

## The governing principle

In OT, response automation must prioritize **safety, process reliability, and mission** over speed of containment (DoW ZT for OT, stated in activity 2.7.1). This inverts the usual IT instinct. Auto-isolating a controller mid-process, or severing an OT communication path, can drive equipment into an unsafe or inconsistent physical state; the response itself becomes the incident. So containment that touches the physical process is **never** automated; it is gated behind human approval with a controlled-recovery procedure (mirroring activity 7.2.1).

## Response tiers

| Tier | Name | Automated actions | Human involvement |
|------|------|-------------------|-------------------|
| **Tier 0** | Observe & enrich | Asset-context lookup, MITRE ATT&CK for ICS tagging, severity set, incident comment, route/notify, open ticket | None required; analyst reviews enriched incident |
| **Tier 1** | Conditional IT-side containment | The above, **plus** containment that affects only IT-side / DMZ assets (e.g., disable an IT account, block at the IT-facing firewall, quarantine an engineering workstation that sits in the IT/OT DMZ) | Auto only when asset context confirms the target is IT-side and non-critical; otherwise escalates to Tier 2 |
| **Tier 2** | Approval-gated OT containment | The Tier 0 actions only. Any containment touching an OT asset (isolation, command blocking, path disconnect) is **proposed**, not executed | Mandatory approval (Teams adaptive card / email) before action; controlled-recovery procedure on reconnect |

## Asset context that drives tier assignment

Tiering is not fixed per detection; it is computed from the affected asset using two lookups, because the synthetic telemetry assigns random host addresses within fixed plant subnets rather than stable per-host IPs:

- **Subnet lookup** (`ot-subnet-context`, matched on the detection's `DestinationIP` by CIDR): gives `zone`, `plant`, `purdue_level`, `owner_team`, `poc_contact`, `maintenance_window`.
- **Role lookup** (`ot-role-context`, matched on the asset role in the event): gives `device_class` and `criticality` (for example, `SafetyController` maps to safety_critical).

**Escalation rule:** tier escalates as Purdue level decreases (closer to the physical process) and as criticality increases. **Any asset at Purdue level ≤ 2, or flagged safety-critical, is forced to Tier 2** regardless of the detection's default.

## The matrix

Each row maps to an actual v1 detection query. Tiers are driven by asset context, so they hold regardless of tuning changes to the queries themselves.

| Detection (query) | Source / rule IDs | ATT&CK for ICS | Typical affected asset | Default tier | Rationale |
|---|---|---|---|---|---|
| WorldView IOC match (`01-worldview-ioc-match.kql`) | Dragos WorldView | threat-intel match (named actor) | Varies | **Tier 1, escalates to Tier 2** | Highest-fidelity alert (named actor: VOLTZITE, ELECTRUM, etc.). Auto-isolate only if the asset is IT-side; gate if it is an OT controller or HMI. Enrich with `WorldViewActor` and `DragosCaseId`. |
| PLC program download (`02-plc-program-download.kql`) | Dragos ENI-014 / eyeInspect ITL-2034 | T0843 Program Download | PLC + engineering workstation (L1/L2) | **Tier 2** | Often legitimate engineering work; auto-blocking can leave the PLC inconsistent. Check the approved change window and engineering-host watchlist, page engineering, gate any block. |
| PLC mode change to PROGRAM (`03-plc-mode-change.kql`) | Dragos / Forescout | T0858 Change Operating Mode | PLC/RTU (L1) | **Tier 2 (forced)** | A RUN to PROGRAM switch halts process control and can stop a line. Never auto-act; immediate page; gated containment with controlled recovery. |
| Safety controller write (`04-safety-controller-write.kql`) | Dragos / Forescout (Modbus) | T0836 Modify Parameter | Safety controller / SIS (L1, safety-critical) | **Tier 2 (forced)** | Highest priority of any detection here. Acting on a safety-controller path is itself hazardous; human escalation only, gated, controlled recovery. |
| Segmentation policy blocked (`05-segmentation-policy-blocked.kql`) | Forescout eyeSegment (Action = Block) | n/a (segmentation event) | Boundary / cross-zone (L3.5) | **Tier 0, conditional Tier 1** | eyeSegment already blocked the attempt, so SOAR has nothing to contain. Enrich and investigate the attempt; if `RiskScore` is high (OT outbound to Internet), optionally disable the source host or block IT-side (Tier 1). |
| Cross-platform correlation (`06-cross-platform-correlation.kql`) | Dragos + eyeInspect (joined on asset) | inherits underlying alerts | PLC / controller (`DestinationIP`) | **Inherits highest, default Tier 2** | Two independent sensors flagging the same asset is high-confidence. Raise `CombinedSeverity`, open a high-priority incident, page the OT engineer; gate containment since the correlated asset is typically an OT controller. |

## Considered, not implemented in v1 (v2 backlog)

These were in the analysis space but have no matching query today. They are recorded here so the matrix shows the full reasoning and doubles as a detection backlog. Each would inherit a tier under the same rules if built.

- Controller firmware change (T0857 System Firmware): Tier 2.
- Standalone unauthorized command message (T0855), separate from the safety-controller case: Tier 2.
- eyeInspect protocol / policy violation (T0856 Spoof Reporting Message): Tier 0.
- New or unknown asset on OT network (inventory event): Tier 0, manual escalation.
- Asset vulnerability detected (posture): Tier 0, ticket to OT vulnerability management, never auto-patch.
- Loss of communication / device offline (T0815 Denial of Service): Tier 0; acting could worsen an availability event.
- Standalone lateral movement between OT zones (T0859 Valid Accounts): Tier 2; currently covered indirectly by the segmentation-blocked query.
| Loss of communication / device offline | Dragos / eyeInspect | T0815 Denial of Service | Varies | **Tier 0** | This is itself an availability/safety event; automated action could worsen it. Immediate page, no auto-response. |

## Approval & controlled recovery (Tier 2)

For any Tier 2 action, the gated-containment playbook:

1. Posts the proposed action, affected asset context, and detection detail to the asset's `owner_team` for approval.
2. Executes (or, in the lab, **simulates**) the action only on explicit approval.
3. Records the action and a controlled-recovery checklist on the incident, so reconnection is deliberate and validated rather than automatic (activity 7.2.1).

## Crosswalk

| Artifact / behavior here | DoW ZT for OT activity |
|---|---|
| This matrix (the analysis itself) | 6.5.1 |
| Playbooks that implement it | 6.5.2 |
| Documented OT IR process built on it | 6.7.1 |
| Asset-ID-driven response | 7.2.5 (outcome 3) |
| Gated isolation + controlled recovery | 7.2.1 |
| Advanced/enriched playbooks | 6.7.2 |
