# OT Asset-Context Watchlists

> Repo path: `soar/watchlists/`
> Files: `ot-subnet-context.csv`, `ot-role-context.csv`, and this schema doc.
> Supports **7.2.5** (asset-ID correlation) and is the data source for every tier decision in `decision-matrix.md`.

## Why two lookups, not one host table

The synthetic generator (`ot_log_generator.py`) assigns a **random host address** within a fixed plant subnet on every event, so there are no stable per-host IPs to key on. A watchlist keyed on an exact host IP would almost never match. The attributes that are stable and meaningful in the data are:

- the **subnet**, which fixes the plant and the Purdue level, and
- the **asset role** (`EngineeringWorkstation`, `PLC`, `SafetyController`, etc.), carried in the CEF custom strings.

So enrichment uses two small lookups, joined to those two stable attributes.

## Lookup 1: `ot-subnet-context`

Matched on the detection's `DestinationIP` by CIDR (the affected asset).

| Field | Purpose |
|---|---|
| `subnet` | SearchKey. CIDR matched against `DestinationIP`. |
| `zone` | Human-readable zone (Plant-A-L2, Engineering-DMZ, etc.). |
| `plant` | Site grouping for routing. |
| `purdue_level` | 1, 2, 3, 3.5 (IT/OT DMZ), 4. Primary driver of the tier floor. |
| `owner_team` | Drives routing and notification. |
| `poc_contact` | Approval recipient for any Tier 2 gated action. |
| `maintenance_window` | Suppresses program-download (02) and mode-change (03) false positives during approved windows. |

## Lookup 2: `ot-role-context`

Matched on the asset role carried in the event. For destination assets that is `DeviceCustomString2` (rendered as `DestRole` by Dragos and `DstAssetRole` by eyeInspect).

| Field | Purpose |
|---|---|
| `asset_role` | SearchKey. Matches the role string in the event. |
| `device_class` | PLC, RTU, IED, DCSController, SIS, EWS, HMI, Historian, IT_Host. |
| `criticality` | safety_critical, process_critical, support. `SafetyController` maps to safety_critical. |

## How a playbook computes the effective tier

```
rule_floor = 2 if (purdue_level <= 2 OR criticality == "safety_critical") else 0
effective_tier = max(detection_default_tier, rule_floor)
```

`purdue_level` comes from the subnet lookup; `criticality` comes from the role lookup; `detection_default_tier` comes from `decision-matrix.md`. The playbook takes the highest, so safety always wins.

## KQL enrichment pattern

```kusto
let subnets = _GetWatchlist('ot-subnet-context');
let roles   = _GetWatchlist('ot-role-context');
CommonSecurityLog
| where DeviceVendor in~ ("Dragos", "Forescout")
| extend DstRole = tostring(DeviceCustomString2)
| evaluate ipv4_lookup(subnets, DestinationIP, subnet)        // CIDR match on the affected asset
| lookup kind=leftouter roles on $left.DstRole == $right.asset_role
| extend RuleFloor = iff(todouble(purdue_level) <= 2 or criticality == "safety_critical", 2, 0)
| project TimeGenerated, DeviceVendor, Activity, DestinationIP,
          zone, plant, purdue_level, device_class, criticality,
          owner_team, poc_contact, maintenance_window, RuleFloor
```

`ipv4_lookup` is the built-in plugin for CIDR matching against a table; it avoids a manual cross-join.

## Creating the watchlists in Sentinel

For each file: Microsoft Sentinel > Configuration > Watchlists > New.

| Alias | File | SearchKey |
|---|---|---|
| `ot-subnet-context` | `ot-subnet-context.csv` | `subnet` |
| `ot-role-context` | `ot-role-context.csv` | `asset_role` |

## Note on tier reachability in the current data

In the generator, Dragos and eyeInspect events always place source and destination in the three plant subnets (`_rand_ot_endpoint` draws from the plant subnets only). Every affected asset is therefore Purdue 1 or 2, so the rule floor is 2 and OT detections resolve to Tier 2. The Tier 1 branch (auto-isolate an IT-side asset, for example a WorldView IOC match on a jump host) is only exercised if you extend the generator to emit IT-side destinations. Worth knowing if you want to demo the auto-containment path end to end.
