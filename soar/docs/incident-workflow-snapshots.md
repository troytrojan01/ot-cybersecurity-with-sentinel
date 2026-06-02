# SOAR incident workflow snapshots

These screenshots show the optional SOAR extension after Sentinel incidents have moved through enrichment, ticketing, and gated containment. Use them as a visual reference for what a working run should leave behind in the incident queue and what the human approver sees in email.

## Cross-Platform Correlation

This incident demonstrates the multi-sensor correlation path where Dragos and Forescout activity share an affected destination asset. The SOAR output shows response tags, ticketing evidence, enrichment fields, and the high-confidence incident details.

![Cross-platform correlation incident overview](assets/incident-workflow/01-incidents-cross-platform-overview.png)

![Cross-platform correlation response tags and ticket comment](assets/incident-workflow/02-cross-platform-tags-ticket-comment.png)

![Cross-platform correlation evidence, entities, and analytics rule details](assets/incident-workflow/03-cross-platform-incident-details.png)

![Cross-platform correlation approval email with approve and reject options](assets/incident-workflow/10-approval-cross-platform-correlation.jpg)

## PLC Mode Change to Program

This incident demonstrates a Tier 2 operational-impact detection. The expected result is a high-severity incident with enrichment tags, a ticketing comment, `tier-2`, `pending-controlled-recovery`, and `contained-sim` after approval-gated containment runs.

![PLC mode change ticket comment and incident fields](assets/incident-workflow/04-plc-mode-ticket-comment.png)

![PLC mode change response tags and ticket comment](assets/incident-workflow/05-plc-mode-tags-ticket-comment.png)

![PLC mode change evidence, entities, and MITRE context](assets/incident-workflow/06-plc-mode-incident-details.png)

![PLC mode change approval email with approve and reject options](assets/incident-workflow/11-approval-plc-mode-change.jpg)

## WorldView IOC Match

This incident demonstrates the threat-intelligence path for Dragos WorldView matches. The screenshots show the ticket comment, safety-critical response context, enrichment tags, evidence count, affected entities, and analytics rule details.

![WorldView IOC Match ticket comment and incident fields](assets/incident-workflow/07-worldview-ticket-comment.png)

![WorldView IOC Match safety-critical tags and ticket comment](assets/incident-workflow/08-worldview-tags-ticket-comment.png)

![WorldView IOC Match evidence, entities, and MITRE context](assets/incident-workflow/09-worldview-incident-details.png)

![WorldView IOC Match approval email showing safety-controller handling](assets/incident-workflow/12-approval-worldview-ioc-match.jpg)
