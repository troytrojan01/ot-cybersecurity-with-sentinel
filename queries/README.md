# KQL Query Library

A working set of queries for OT data flowing through `CommonSecurityLog`. Organized by intent, not by data source — most queries cover all three platforms (Dragos, eyeInspect, eyeSegment).

## How to use these

Most files are standalone — paste into the Sentinel **Logs** blade and run. A few queries reference parser functions defined in [`parsers/`](parsers/) — save those first as Sentinel functions (via **Save → Save as function** in the Logs blade) so the other queries can call them by name.

Recommended path:

1. Start with [`exploration/`](exploration/) to confirm data is flowing
2. Save the functions in [`parsers/`](parsers/) — they get used by everything downstream
3. Use [`detections/`](detections/) as templates for analytics rules
4. Use [`hunting/`](hunting/) for analyst-driven investigation
5. Use [`operations/`](operations/) to monitor pipeline health and cost

## Index

### Exploration — confirm data is flowing
- [01-ingestion-overview.kql](exploration/01-ingestion-overview.kql) — what's coming in, by vendor and product
- [02-recent-events-all-platforms.kql](exploration/02-recent-events-all-platforms.kql) — last 100 OT events with full context
- [03-severity-distribution.kql](exploration/03-severity-distribution.kql) — event volume by severity, per platform
- [04-event-rate-over-time.kql](exploration/04-event-rate-over-time.kql) — timechart for spotting ingestion gaps

### Parsers — save these as functions first
- [Dragos_Events.kql](parsers/Dragos_Events.kql) — pulls Dragos custom fields out of `AdditionalExtensions`
- [eyeInspect_Events.kql](parsers/eyeInspect_Events.kql) — eyeInspect normalized view
- [eyeSegment_Events.kql](parsers/eyeSegment_Events.kql) — eyeSegment normalized view
- [OT_Events_Unified.kql](parsers/OT_Events_Unified.kql) — union of all three platforms with a consistent schema

### Detections — analytics-rule-shaped queries
- [01-worldview-ioc-match.kql](detections/01-worldview-ioc-match.kql) — Dragos events tied to a named ICS threat actor
- [02-plc-program-download.kql](detections/02-plc-program-download.kql) — program downloads to PLC (T0843)
- [03-plc-mode-change.kql](detections/03-plc-mode-change.kql) — PLC mode change to PROGRAM (T0858)
- [04-safety-controller-write.kql](detections/04-safety-controller-write.kql) — any Modbus write targeting a safety controller
- [05-segmentation-policy-blocked.kql](detections/05-segmentation-policy-blocked.kql) — eyeSegment block actions (something tried to cross zones)
- [06-cross-platform-correlation.kql](detections/06-cross-platform-correlation.kql) — Dragos + eyeInspect alerts on the same asset within 5 min

### Hunting — open-ended queries for analysts
- [01-mitre-ics-technique-frequency.kql](hunting/01-mitre-ics-technique-frequency.kql) — heatmap of techniques observed
- [02-zone-pair-traffic.kql](hunting/02-zone-pair-traffic.kql) — top-talker zone pairs
- [03-off-hours-engineering-activity.kql](hunting/03-off-hours-engineering-activity.kql) — engineering tool use outside business hours
- [04-rare-protocols-to-controllers.kql](hunting/04-rare-protocols-to-controllers.kql) — unusual protocols hitting PLCs

### Operations — health and cost
- [01-parser-coverage.kql](operations/01-parser-coverage.kql) — events where IPs failed to parse (canary for the RFC 3164 bug)
- [02-ingestion-volume-by-platform.kql](operations/02-ingestion-volume-by-platform.kql) — GB ingested per day, for cost tracking

## Conventions

- **Time filter goes first** — `where TimeGenerated > ago(1h)` always early in the pipeline, so Log Analytics can prune partitions before scanning columns.
- **Use `in~` for case-insensitive vendor matches** — `DeviceVendor in~ ("dragos", "forescout")` rather than worrying about casing.
- **Use `extract()` patterns from the parsers** for custom fields — don't repeat the regex inline in every detection.
- **Severity in CEF is 0–10** — `LogSeverity` is a string in `CommonSecurityLog`, so cast with `toint()` before comparing.
