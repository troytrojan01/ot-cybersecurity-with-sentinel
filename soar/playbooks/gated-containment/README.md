# Playbook: Approval-Gated Containment

> Repo path: `soar/playbooks/gated-containment/`
> Files: `gated-containment.azuredeploy.json` (the Logic App) and this README.
> Implements the Tier 2 path from `decision-matrix.md` and the controlled-recovery requirement of activity **7.2.1**. This is the playbook that makes the difference between OT-safe response and generic SOC automation.

## The design idea

In OT, automated containment that touches a live process can be more dangerous than the incident. So this playbook never acts on its own. For a Tier 2 incident it proposes a containment action, routes that proposal to the asset's owner for a human decision, and acts only on explicit approval. On approval it records a controlled-recovery checklist so reconnection is deliberate rather than automatic. In the lab the containment action is simulated; the decision flow and documentation are the real artifact.

## Flow

1. Trigger on incident creation.
2. **Guard:** proceed only if the incident carries the `tier-2` tag written by the enrichment playbook. Otherwise terminate as a no-op.
3. Read the affected asset IP, re-run the watchlist lookups to get `device_class`, `criticality`, `zone`, `owner_team`, and `poc_contact`.
4. Build a proposed action appropriate to the device class:
   - SIS / safety controller: do not auto-isolate; coordinate manually with Safety Systems, isolate only after safe-state confirmation.
   - PLC / RTU / IED / DCS controller: propose logical isolation at the zone boundary and blocking the offending control path.
   - HMI / engineering workstation: propose quarantine and OT-access revocation.
5. Send an approval email to `poc_contact` with the asset context, the proposed action, and a link to the incident.
6. **On Approve:** write the approved action plus the controlled-recovery checklist as a comment, set the incident Active, and tag it `contained-sim` and `pending-controlled-recovery`. (The real isolation call is left as a simulated step in the lab.)
7. **On Reject:** comment that containment was declined and leave the incident for manual handling by `owner_team`, tagged `containment-declined`.

## Prerequisites

- The enrichment-triage playbook runs first and applies the `tier-2` tag. Wire both into one automation rule with enrichment ordered first, so the guard sees the tag.
- Watchlists `ot-subnet-context` and `ot-role-context` exist.
- Analytics rules map `DestinationIP` as the IP entity (same requirement as the enrichment playbook).

## Deploy

1. Deploy `azuredeploy.json` from **Sentinel > Automation > Import**. Supply `WorkspaceName`. If Import is not available or rejects the template, use Azure portal **Deploy a custom template** or `az deployment group create`.
2. Authorize the three API connections: `azuresentinel`, `azuremonitorlogs`, and `office365` (sign in as the mailbox that will send approval requests).
3. Grant the Logic App's managed identity Microsoft Sentinel Responder on the workspace.
4. Add this playbook as the second action (after enrichment) in the OT automation rule, or as its own automation rule conditioned on tag contains `tier-2`.

## Where the real containment call goes

Step 6 is intentionally a simulated action. To make it real later, replace the simulated step with the actual integration for your environment, for example a firewall or NAC API call, or a Defender action, placed after the approval branch so it can only ever run post-approval. Keep it after the approval so the human gate is structurally guaranteed, not just procedural.

## Notes and caveats

- The Office 365 "Send approval email" action waits for the recipient to choose Approve or Reject. For Teams-based approval instead, swap that single action for the Teams "Post adaptive card and wait for a response" action; the branch logic is unchanged.
- As with the enrichment playbook, exact Sentinel and Outlook connector action shapes can vary by connector version. If one action fails validation, re-add it in the designer; the gating logic is the substance.
- For a safety controller (SIS), the proposed action deliberately recommends against automated isolation even with approval, reflecting that safety systems get manual, coordinated handling.
