# Sentinel dashboard snapshots

These snapshots show the lab data after the generator has been ingested into Microsoft Sentinel's `CommonSecurityLog` table. They are useful as quick visual confirmation of the expected query shape, normalized fields, and summary views.

## Raw OT event flow

CommonSecurityLog results from Dragos and Forescout events over the last hour.

![CommonSecurityLog event results](assets/sentinel-dashboard/01-commonsecuritylog-event-results.png)

## Custom field mapping

The same event flow with the custom string fields visible. These fields carry OT-specific context such as zones, MITRE technique IDs, rule categories, and policy actions.

![CommonSecurityLog custom fields](assets/sentinel-dashboard/02-commonsecuritylog-custom-fields.png)

## Forescout eyeInspect rule summary

eyeInspect events grouped by rule category and activity.

![Forescout eyeInspect rule summary](assets/sentinel-dashboard/03-eyeinspect-rule-summary.png)

## Forescout eyeSegment policy summary

eyeSegment policy violations grouped by source zone, destination zone, action, and policy.

![Forescout eyeSegment policy violations](assets/sentinel-dashboard/04-eyesegment-policy-violations.png)

## Dragos MITRE summary

Dragos Platform detections grouped by activity, MITRE ATT&CK for ICS technique, and analytic type.

![Dragos MITRE summary](assets/sentinel-dashboard/05-dragos-mitre-summary.png)

## Vendor activity summary

Top generated activities by vendor and product.

![Vendor activity summary](assets/sentinel-dashboard/06-vendor-activity-summary.png)
