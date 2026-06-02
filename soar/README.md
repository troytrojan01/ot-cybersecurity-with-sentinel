# OT SOAR and Response (optional v2 extension)

> Repo path: `soar/`

This folder is an **optional extension** to the v1 OT monitoring lab. The v1 monitoring lab (synthetic Dragos and Forescout telemetry into Microsoft Sentinel, parsers, and the detection analytics rules) is fully standalone. If you only want OT detection and monitoring, you can ignore this entire folder. The SOAR layer adds the response side: asset enrichment, response tiering, and approval-gated containment with controlled recovery.

## Layout

```
soar/
  README.md                         (this file)
  decision-matrix.md                response-automation analysis (6.5.1)
  watchlists/
    ot-subnet-context.csv           subnet -> Purdue level, zone, owner, contact
    ot-role-context.csv             asset role -> device class, criticality
    watchlist-schema.md             field reference and KQL pattern
  playbooks/
    enrichment-triage/              azuredeploy.json + README
    gated-containment/              azuredeploy.json + README
    ticketing/                      azuredeploy.json + README
  docs/
    incident-workflow-snapshots.md  screenshots of working SOAR incidents
    ot-ir-runbook.md                documented OT IR process (6.7.1)
```

## What you need in place first

- v1 deployed and ingesting: a Sentinel workspace with `CommonSecurityLog` receiving the Dragos and Forescout synthetic telemetry (rsyslog to AMA to `CommonSecurityLog`).
- Parser functions from `queries/parsers/` saved in Sentinel. At minimum, `WorldView IOC Match` needs the `Dragos_Events` function.
- The six detections from `queries/detections/` deployed as Sentinel scheduled analytics rules. Use [`../queries/analytics-rule-setup.md`](../queries/analytics-rule-setup.md) for the parser prerequisites, exact rule names, cadence, and entity mapping.
- Rights to create watchlists, deploy Logic Apps, create automation rules, and assign Azure roles.

## Setup in Sentinel, in order

### Step 1: Create the two watchlists
Sentinel > Configuration > Watchlists > New, once per file:

| Alias | File | SearchKey |
|---|---|---|
| `ot-subnet-context` | `ot-subnet-context.csv` | `subnet` |
| `ot-role-context` | `ot-role-context.csv` | `asset_role` |

The sample rows match the shipped `ot_log_generator.py`. If you change the generator's subnets or roles, update the CSVs to match.

### Step 2: Prepare the analytics rules
Before creating rules, save the parser functions described in [`../queries/analytics-rule-setup.md`](../queries/analytics-rule-setup.md). If Sentinel reports `Failed to resolve table or column expression named 'Dragos_Events'`, the `Dragos_Events` parser has not been saved as a function in the workspace.

For each of the six detection rules:

1. **Map `DestinationIP` as the IP entity** (Address identifier). The playbooks read the single IP entity as the affected asset, so map the destination, not the source. Keep `SourceIP` as a custom detail if you want it on the incident.
2. **Name the rule to match the tier map.** The enrichment playbook keys default tiers on these display names: `WorldView IOC Match`, `PLC Program Download`, `PLC Mode Change to Program`, `Safety Controller Write`, `Segmentation Policy Blocked`, `Cross-Platform Correlation`. Use these names or edit the `detectionTierMap` variable in the enrichment playbook.
3. **Set cadence** per the comment in each `.kql` (most are every 5 minutes, 10 minute lookback).
4. Leave incident creation and alert grouping at the default so each detection produces an incident.

### Step 3: Deploy the playbooks
Deploy the ARM templates from Sentinel Automation using **Import**. The **Create** menu is for building new blank playbooks and may not show a custom-template option.

Recommended portal path:

1. Open **Microsoft Sentinel > Automation** for your workspace.
2. Select **Import** from the top toolbar.
3. Import each playbook template:
   - `soar/playbooks/enrichment-triage/azuredeploy.json`
   - `soar/playbooks/gated-containment/azuredeploy.json`
   - `soar/playbooks/ticketing/azuredeploy.json` if you want queue-mailbox ticketing
4. Set `WorkspaceName` to your Sentinel workspace name.
5. Leave `PlaybookName` at the default unless you intentionally renamed the workflow.
6. For the ticketing playbook, also set `TicketQueueAddress` to the mailbox or distribution list that should receive tickets.

If **Import** does not accept the template in your tenant, use Azure portal **Deploy a custom template** instead: search for **Deploy a custom template**, choose **Build your own template in the editor**, load the same `azuredeploy.json`, then supply the same parameters. The Azure CLI equivalent is `az deployment group create`.

After deployment, authorize the API connections:

- enrichment-triage: `azuresentinel`, `azuremonitorlogs`
- gated-containment: `azuresentinel`, `azuremonitorlogs`, `office365` (sign in as the mailbox that sends approval requests)
- ticketing: `azuresentinel`, `azuremonitorlogs`, `office365` (sign in as the mailbox that sends ticket emails)

Then grant each playbook's system-assigned managed identity the **Microsoft Sentinel Responder** role on the workspace so it can comment on and update incidents. The query path works through the authorized `azuremonitorlogs` connection; if you switch to identity-based auth, also grant **Log Analytics Reader**.

### Step 4: Wire the automation rule
Sentinel > Automation > Create > Automation rule:

- Trigger: When incident is created.
- Condition (optional): scope to your OT analytics rules by rule name or analytics rule id.
- Actions, in this exact order:
  1. Run playbook: `OT-Enrichment-Triage`
  2. Run playbook: `OT-Ticketing`, if deployed
  3. Run playbook: `OT-Gated-Containment`

Order matters. Enrichment must run first so the `tier-2` tag exists when the containment playbook's guard checks for it. Ticketing can run after enrichment so the ticket includes the enriched tags and owner context. If prompted, grant Sentinel permission to run playbooks: the **Microsoft Sentinel** service identity needs the **Microsoft Sentinel Playbook Operator** role on the resource group that holds the playbooks.

### Step 5: Test the loop
Generate events so the analytics rules fire. For example, stream CEF from the generator to your syslog collector:

```
python ot_log_generator.py --stream --rate 2 \
    --syslog-host <collector-ip> --syslog-port 514 --syslog-proto udp
```

Then watch one incident move through the pipeline: incident created, enrichment comment and severity and `tier-N` tag applied, and for a Tier 2 incident an approval email sent to the asset POC. Approve to see the approved comment with the controlled-recovery checklist and the `pending-controlled-recovery` tag; reject to see the incident left for manual handling. `decision-matrix.md` explains why each detection lands where it does, and `docs/ot-ir-runbook.md` describes the full process.

For examples of the expected incident output, see the [SOAR incident workflow snapshots](docs/incident-workflow-snapshots.md). They show enriched Sentinel incidents, ticket comments, response-tier tags, containment and recovery tags, evidence, entities, and analytics-rule details after the automation rule runs.

## How the pieces fit

- `decision-matrix.md` is the policy: which detection gets which response tier and why.
- The watchlists are the asset context: they turn an IP into a Purdue level, criticality, owner, and contact, and they set the safety floor.
- The enrichment playbook applies the policy to each incident: it looks up the asset, computes the effective tier, and writes context, severity, and tags.
- The ticketing playbook creates the ops ticket email and records the ticket reference as an incident comment.
- The gated-containment playbook is the human gate: for Tier 2 it proposes a device-appropriate action, waits for approval, and records controlled recovery.
- The runbook is the documented process that wraps all of the above.

## What is deliberately not automated

Containment that touches a live OT process is never automated. Tier 2 actions are proposed and executed only on human approval, and safety controllers are handled manually even with approval. This is the core of the design, not a limitation.

## Notes on connectors

Exact Sentinel and Outlook connector action shapes can vary by connector version. If a single action fails validation on deploy or run, open the workflow in the Logic Apps designer and re-add that action; the surrounding logic and data flow are the substance. The playbook READMEs call out the specific actions where this applies.

## Mapping to DoW ZT for OT

The crosswalk from each artifact to its activity id is in `decision-matrix.md` and `docs/ot-ir-runbook.md` (section 11). In short: 6.5.1 (analysis), 6.5.2 (SOAR tools), 6.7.1 (documented IR), 7.2.1 (isolation and controlled recovery), 7.2.5 (asset-ID-driven response), with a path to 6.7.2 (advanced response).
