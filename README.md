# OT Cybersecurity with Sentinel

End-to-end lab for ingesting OT (operational technology) security telemetry into Microsoft Sentinel. Includes a synthetic log generator that emits realistic Dragos Platform and Forescout (eyeInspect, eyeSegment) events in CEF and JSON, the Azure infrastructure setup to receive them, and a library of KQL queries for exploration, detection, and hunting.

Use this to:

- Develop and test Sentinel parsers, analytics rules, and workbooks for OT data sources without owning Dragos or Forescout appliances
- Onboard new analysts to OT security telemetry patterns (MITRE ATT&CK for ICS, Purdue Level segmentation, industrial protocols)
- Prototype detections before a real OT sensor deployment

## What's in here

```
.
├── generator/              Synthetic OT log generator (Python, stdlib only)
├── queries/                KQL queries organized by intent
│   ├── exploration/        See what's flowing, validate ingestion
│   ├── parsers/            Reusable functions to extract custom fields
│   ├── detections/         Analytics-rule-shaped queries
│   ├── hunting/            Open-ended threat hunting queries
│   └── operations/         Health, cost, parser-quality monitoring
├── docs/                   Architecture, field mappings, MITRE ATT&CK for ICS reference, dashboard snapshots
└── setup/                  Azure infrastructure setup steps
```

## Quick start

1. Stand up the ingestion pipeline — see [`setup/README.md`](setup/README.md)
2. Run the generator on the forwarder VM:
   ```bash
   python3 generator/ot_log_generator.py --stream --rate 2 \
       --syslog-host 127.0.0.1 --syslog-port 514 --syslog-proto udp
   ```
3. Wait ~5 minutes, then run the exploration queries to confirm data is flowing
4. Save the parser functions from `queries/parsers/` so the detection and hunting queries can use them

For examples of what the generated data looks like in Sentinel, see [`docs/sentinel-dashboard-snapshots.md`](docs/sentinel-dashboard-snapshots.md).

## Architecture at a glance

```
┌─────────────────┐    UDP/TCP 514     ┌──────────────────┐
│ ot_log_generator│ ─────────────────▶ │  rsyslog (VM)    │
│   (Python)      │                    │     │            │
└─────────────────┘                    │     ▼ tcp 28330  │
                                       │  Azure Monitor   │
                                       │     Agent        │
                                       └──────────────────┘
                                                │
                                                ▼
                                       ┌──────────────────┐
                                       │ Log Analytics    │
                                       │ workspace        │
                                       │ CommonSecurityLog│
                                       └──────────────────┘
                                                │
                                                ▼
                                       ┌──────────────────┐
                                       │ Microsoft        │
                                       │ Sentinel         │
                                       └──────────────────┘
```

## What the generator produces

Three platforms, two output formats each:

| Platform | Format | What it looks like |
|----------|--------|--------------------|
| Dragos Platform | CEF over syslog | `<134>May 26 13:09:00 dragos-sitestore CEF:0\|Dragos\|Platform\|2.3\|MOD-001\|Unauthorized Modbus Write Detected\|7\|src=10.21.4.47 dst=10.40.2.89 ...` |
| Dragos Platform | REST API JSON | `{"id": "NOTIF-90070", "title": "Unauthorized PLC Program Download", "mitre_ics": ["T0843"], ...}` |
| Forescout eyeInspect | CEF over syslog | `<132>May 26 13:09:00 eyeinspect-cc CEF:0\|Forescout\|eyeInspect\|5.4.0\|ITL-2034\|...` |
| Forescout eyeInspect | REST API JSON | `{"alert_id": 543210, "rule_category": "IndustrialThreatLibrary", ...}` |
| Forescout eyeSegment | CEF over syslog | `<134>May 26 13:09:00 forescout-platform CEF:0\|Forescout\|eyeSegment\|2.7.1\|POLVIO-1042\|...` |
| Forescout eyeSegment | REST API JSON | `{"event_id": "POL-EVT-921872", "src_zone": "OT-L2-HMI", "dst_zone": "Internet", ...}` |

Event content uses real MITRE ATT&CK for ICS technique IDs (T0836, T0843, T0855, etc.), realistic OT protocols (Modbus/TCP, S7comm, DNP3, IEC-104, OPC UA, EtherNet/IP), Purdue-aligned asset roles (PLC, RTU, HMI, Historian, Engineering Workstation), and vendor-realistic rule ID conventions.

## Disclaimer

This is a lab tool. The generator emits synthetic events for parser and detection development. It is not affiliated with or endorsed by Dragos, Forescout, or Microsoft. The data formats are modeled from publicly available documentation; live appliance output may differ in subtle ways.

## License

MIT — see `LICENSE`. Contributions welcome.
