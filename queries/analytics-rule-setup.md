# Sentinel analytics rule setup

Use this guide when turning the KQL files in `queries/detections/` into Microsoft Sentinel scheduled analytics rules.

## 1. Confirm data is flowing first

In Sentinel, open **Logs** and run:

```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor in~ ("Dragos", "Forescout")
| summarize Events = count() by DeviceVendor, DeviceProduct
```

Do not create analytics rules until you see Dragos and/or Forescout rows. If this query returns nothing, fix ingestion before tuning detections.

## 2. Save the parser functions

Some detections call parser functions such as `Dragos_Events`. Sentinel will not know those names until you save the parser queries as functions in the workspace.

Save these files from `queries/parsers/` as Sentinel functions, using the exact function names below:

| Save order | File | Function name |
|---:|---|---|
| 1 | `Dragos_Events.kql` | `Dragos_Events` |
| 2 | `eyeInspect_Events.kql` | `eyeInspect_Events` |
| 3 | `eyeSegment_Events.kql` | `eyeSegment_Events` |
| 4 | `OT_Events_Unified.kql` | `OT_Events_Unified` |

Recommended process for each parser:

1. Open **Sentinel > Logs**.
2. Paste the full parser query from the `.kql` file.
3. Select **Save > Save as function**.
4. Set the function name exactly as shown in the table.
5. Use a category such as `OT`.
6. Save.

Save `OT_Events_Unified` last because it depends on the first three functions.

After saving, test the functions:

```kql
Dragos_Events
| take 10
```

```kql
eyeInspect_Events
| take 10
```

```kql
eyeSegment_Events
| take 10
```

```kql
OT_Events_Unified
| take 10
```

If you see an error like:

```text
'where' operator: Failed to resolve table or column expression named 'Dragos_Events'
```

then the `Dragos_Events` function has not been saved, was saved under a different name, or is saved in a different workspace than the analytics rule.

## 3. Create the six scheduled analytics rules

In Sentinel, go to **Analytics > Create > Scheduled query rule**. Use the detection files in `queries/detections/` as the rule queries.

Use these rule names if you plan to use the optional SOAR extension. The enrichment playbook maps response tiers by these exact display names.

| Detection file | Rule name | Severity | Run frequency | Lookup data from the last | Parser dependency |
|---|---|---|---:|---:|---|
| `01-worldview-ioc-match.kql` | `WorldView IOC Match` | High or Critical | 5 minutes | 10 minutes | `Dragos_Events` |
| `02-plc-program-download.kql` | `PLC Program Download` | High | 5 minutes | 10 minutes | None |
| `03-plc-mode-change.kql` | `PLC Mode Change to Program` | Critical | 5 minutes | 10 minutes | None |
| `04-safety-controller-write.kql` | `Safety Controller Write` | Critical | 5 minutes | 10 minutes | None |
| `05-segmentation-policy-blocked.kql` | `Segmentation Policy Blocked` | Medium | 10 minutes | 15 minutes | None |
| `06-cross-platform-correlation.kql` | `Cross-Platform Correlation` | High | 5 minutes | 10 minutes | None |

For `WorldView IOC Match`, save and test `Dragos_Events` before creating the rule.

## 4. Configure entity mapping

For each analytics rule, map the affected asset as the destination IP:

| Entity type | Identifier | Query column |
|---|---|---|
| IP | Address | `DestinationIP` |

Do not map `SourceIP` as the primary IP entity for these lab rules. The optional SOAR playbooks read the single IP entity as the affected asset, and in these detections that asset is the destination.

Recommended custom details:

| Custom detail | Query column |
|---|---|
| `SourceIP` | `SourceIP` |
| `Activity` | `Activity` |
| `RuleId` | `RuleId` |
| `Severity` | `Severity` |
| `Platform` | `Platform` where present |
| `Message` | `Message` |

For `WorldView IOC Match`, also add `WorldViewActor`, `MitreIcsTechnique`, and `DragosCaseId` as custom details.

## 5. Incident settings

Keep these settings simple for the lab:

- Enable incident creation.
- Leave alert grouping at the default unless you are deliberately testing aggregation.
- Let each scheduled rule create incidents independently.

The optional SOAR automation rule triggers when the incident is created, so disabling incident creation prevents the playbooks from running.

## 6. Common fixes

| Symptom | Fix |
|---|---|
| `Failed to resolve table or column expression named 'Dragos_Events'` | Save `queries/parsers/Dragos_Events.kql` as a function named `Dragos_Events` in the same workspace. |
| `Failed to resolve scalar expression named 'DeviceProcessName'` | Pull the latest repo version. The eyeInspect parser uses `column_ifexists("DeviceProcessName", "")` because some Sentinel `CommonSecurityLog` schemas do not expose that optional column. |
| `OT_Events_Unified` fails to save or run | Save `Dragos_Events`, `eyeInspect_Events`, and `eyeSegment_Events` first. |
| Analytics rule validates but never fires | Confirm the rule lookup window matches the query `ago(...)` filter and that new synthetic events are still arriving. |
| SOAR playbook enriches the wrong asset | Confirm entity mapping uses `DestinationIP` as the IP Address entity. |
| Enrichment playbook assigns the wrong tier | Confirm the analytics rule display name exactly matches the rule names in the table above, or update `detectionTierMap` in the playbook. |
