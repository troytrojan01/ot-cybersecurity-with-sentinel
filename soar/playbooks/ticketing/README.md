# Playbook: Ticketing

> Repo path: `soar/playbooks/ticketing/`
> Files: `ticketing.azuredeploy.json` (the Logic App) and this README.
> Implements the "open ticket" part of the Tier 0 baseline in `decision-matrix.md`. It runs for every OT incident, regardless of tier, so there is always a tracking record.

## No ITSM required

This playbook does not depend on ServiceNow, Jira, or any paid ITSM. The default ticket sink is a **queue mailbox**: it emails a structured ticket to an address you choose (a shared mailbox or distribution list), reusing the Office 365 connection you already authorized for approvals. The Sentinel **incident number** is the stable ticket id (`OT-TKT-<number>`), so the ticket is traceable back to the incident and vice versa.

## What it does

1. Trigger on incident creation.
2. Read the affected asset IP and run the watchlist lookups for context.
3. Collect the incident tags (including the `tier-N` tag from enrichment) and derive a recommended next action from the tier.
4. Send a structured ticket email to the queue address with the ticket id, title, severity, tags, asset context, recommended action, and a link to the incident.
5. Write a comment back on the incident recording the ticket id and the queue it went to.

## Deploy

1. Deploy `azuredeploy.json` from **Sentinel > Automation > Import**. Supply `WorkspaceName` and `TicketQueueAddress` (the mailbox or list that acts as your queue). If Import is not available or rejects the template, use Azure portal **Deploy a custom template** or `az deployment group create`.
2. Authorize the three connections: `azuresentinel`, `azuremonitorlogs`, `office365` (sign in as the sender).
3. Grant the managed identity Microsoft Sentinel Responder on the workspace.
4. In the OT automation rule, add this as the middle action: run enrichment first (so tags and context exist), then ticketing, then gated containment.

## Swapping the ticket sink

The ticket is created by a single action, `Create_ticket_send_to_queue`. To use a different backend, replace just that one action and leave everything else. Common Microsoft-native options, none requiring a paid ITSM:

| Backend | Connector / action | Notes |
|---|---|---|
| Queue mailbox (default) | Office 365 Outlook, Send an email | Zero new setup; reuses the approval connection. |
| Microsoft Planner | Planner, Create a task | Assignable tasks with buckets as status; needs a plan and group id. |
| SharePoint list | SharePoint, Create item | A real ticket register with custom columns and views; needs a site and list. |
| Azure DevOps | Azure DevOps, Create a work item | Good if you already use Boards; needs an org and project. |
| GitHub Issues | GitHub, Create issue | Fits a portfolio repo; use a private ops repo so incident detail is not public. |

Keep the ticket id as the incident number in whichever backend you choose, so the cross-reference between ticket and incident holds.

## Notes

- This playbook runs for all tiers, so a Tier 0 informational incident still produces a ticket for tracking. If you prefer to ticket only at Tier 1 and above, add a guard like the one in the gated-containment playbook that checks the incident tags.
- As with the other playbooks, connector action shapes vary by version; if the send action fails validation, re-add it in the designer.
