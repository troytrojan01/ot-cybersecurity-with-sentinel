# Playbook: Enrichment and Triage

> Repo path: `soar/playbooks/enrichment-triage/`
> Files: `enrichment-triage.azuredeploy.json` (the Logic App) and this README.
> Implements the Tier 0 baseline from `decision-matrix.md` (enrich, set severity, tag) and computes the effective response tier that every downstream playbook reads.

## What it does

On incident creation it:

1. Reads the affected asset IP from the incident's IP entity.
2. Runs one KQL query that does both watchlist lookups: subnet by CIDR (`ipv4_lookup` against `ot-subnet-context`) and role (`ot-role-context`), and returns the asset context plus the `RuleFloor`.
3. Looks up the detection's default tier from an inline map keyed on the analytics rule name.
4. Sets `effective_tier = max(default tier, rule floor)`, so safety always wins.
5. Writes an enrichment comment to the incident, sets severity from the tier, and adds tags (`OT-SOAR`, `tier-N`, criticality, zone).

## Prerequisites

- **Watchlists created**: `ot-subnet-context` and `ot-role-context` (see `../../watchlists/`).
- **Analytics rules map the affected asset as the IP entity**: map `DestinationIP` (not `SourceIP`) to the IP entity in each of the six detection rules. The playbook reads the single IP entity as the affected asset, which avoids ambiguity between source and destination. Keep `SourceIP` as an informational custom detail if you want it on the incident.
- **Analytics rule display names match the tier map keys** in the Logic App variable `detectionTierMap`:

  | Rule display name | Default tier |
  |---|---|
  | WorldView IOC Match | 1 |
  | PLC Program Download | 2 |
  | PLC Mode Change to Program | 2 |
  | Safety Controller Write | 2 |
  | Segmentation Policy Blocked | 0 |
  | Cross-Platform Correlation | 2 |

  If your rule names differ, either rename the rules or edit the map. Unmapped names default to 0, and the rule floor still applies.

## Deploy

1. Deploy `azuredeploy.json` from **Sentinel > Automation > Import**. Supply `WorkspaceName`; the subscription and resource group default to the deployment target. If Import is not available or rejects the template, use Azure portal **Deploy a custom template** or `az deployment group create`.
2. Authorize the two API connections (`azuresentinel`, `azuremonitorlogs`) after deployment.
3. The Logic App is created with a system-assigned managed identity. Grant it the roles it needs: Microsoft Sentinel Responder on the workspace (to comment and update incidents) and Log Analytics Reader (to run the query). Authorizing the connections covers the classic path; the managed identity is there if you switch the connections to identity-based auth.
4. Create a Sentinel automation rule: trigger "When incident is created", condition optionally scoped to your OT analytics rules, action "Run playbook" -> this playbook.

## Effective-tier logic

```
default_tier = detectionTierMap[ incident analytics rule name ]   (else 0)
rule_floor   = 2 if (purdue_level <= 2 OR criticality == "safety_critical") else 0
effective    = max(default_tier, rule_floor)
severity      = High (tier 2), Medium (tier 1), Informational (tier 0)
```

The default tier is the detection's own assessment from the matrix. The rule floor is the asset-driven safety override from the watchlists. Taking the max means an asset can raise a tier but never lower it.

## Notes and caveats

- The affected-asset IP is injected into the KQL as a string. In production, treat entity values as untrusted input; in this lab the values come from controlled Sentinel entities.
- Sentinel connector action shapes (paths such as `/Incidents/Comment` and `/Incidents`, and the `tagsToAdd` structure) vary slightly across connector versions. If a deploy-time or run-time validation complains, open the workflow in the designer and re-add that single action; the surrounding logic and data flow are the substance of this scaffold.
- This playbook performs only Tier 0 actions (enrich, severity, tags). It does not contain anything. Containment is handled by the routing, ticketing, and approval-gated playbooks, which read the `tier-N` tag and the comment this playbook writes.
