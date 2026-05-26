# Architecture

How the lab fits together end to end.

## Components

| Component | Where it runs | Role |
|-----------|---------------|------|
| `ot_log_generator.py` | On the forwarder VM (or anywhere with network access to it) | Produces synthetic CEF events and writes them to a syslog socket |
| `rsyslog` | Forwarder VM, port 514 (UDP/TCP) | Receives raw syslog messages and forwards them to AMA |
| Azure Monitor Agent | Forwarder VM, local socket 28330 | Picks up CEF-formatted messages from rsyslog and ships them to Log Analytics |
| Data Collection Rule | Azure control plane | Tells AMA which workspace and which stream (`Microsoft-CommonSecurityLog`) to ship to |
| Log Analytics workspace | Azure | Stores events in the `CommonSecurityLog` table |
| Microsoft Sentinel | Sentinel pane over the workspace | Provides KQL Logs blade, analytics rules, workbooks, hunting |

## Why this shape

The Sentinel CEF connector requires CEF over syslog — there's no direct "post CEF events to an API" path for `CommonSecurityLog`. So we need a syslog daemon to receive on 514 and a local agent (AMA) to bridge into Log Analytics. The installer script Microsoft provides configures both pieces and creates a forwarding rule from rsyslog to AMA's local socket.

By running the generator on the same VM as rsyslog, we keep all the network traffic on the loopback interface and avoid every NSG, firewall, and policy question that comes with cross-host syslog.

## Data flow timeline

| Step | Latency | What happens |
|------|---------|--------------|
| Generator emits event | <1 ms | Python writes a UDP packet to 127.0.0.1:514 |
| rsyslog receives | <10 ms | Parses the syslog header, identifies it as CEF |
| rsyslog forwards to AMA | <50 ms | Writes to local TCP 28330 |
| AMA buffers and batches | up to ~30 s | Default batching window for ingestion efficiency |
| Log Analytics ingestion | 1–5 min | Azure-side processing, indexing |
| Visible to KQL queries | 5–10 min total | Once indexed, queryable from Sentinel |

That ~5-minute floor is why the smoke test recommends waiting before assuming the pipeline is broken.

## Schema landing

CEF extensions land in `CommonSecurityLog` columns according to a fixed mapping documented in [field-mapping.md](field-mapping.md). Any extension key not in the standard mapping ends up in `AdditionalExtensions` as a `key=value;` string blob.

The custom string columns (`DeviceCustomString1`–`6`) are per-vendor — each vendor decides what to put in each slot. The parser functions in `../queries/parsers/` normalize this into friendly column names so downstream queries don't have to remember which slot holds what.

## Failure modes

The most common failures, in rough order of frequency:

1. **AMA can't reach Log Analytics endpoints** — outbound 443 to `*.ods.opinsights.azure.com` and friends is required. Check NAT Gateway or firewall egress rules.
2. **DCR not associated with the VM** — the connector page should show the VM under Resources. If not, the agent installed but nothing tells it where to send data.
3. **Syslog framing mismatch** — generator emits RFC 5424 but rsyslog expects RFC 3164 (or vice versa). Symptom: events arrive but with mangled message bodies and empty IP columns.
4. **Wrong stream type in DCR** — set to `Microsoft-Syslog` instead of `Microsoft-CommonSecurityLog`. Events land in the `Syslog` table instead of `CommonSecurityLog`.
5. **Facility/severity scope too narrow** — the DCR's "Collect" tab filters by syslog facility and severity. If you set min severity to `LOG_WARNING` and the generator emits `LOG_INFO`, the events get dropped before AMA forwards them.

The `operations/01-parser-coverage.kql` query is designed to catch failure mode #3 specifically. The others surface in the exploration queries showing zero or unexpected event counts.
