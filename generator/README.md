# OT Log Generator

Synthetic OT security telemetry generator. Standard-library Python only (no `pip install` required) — runs anywhere Python 3.10+ is available.

## Quick usage

```bash
# 100-event batch to ./out/
python3 ot_log_generator.py --count 100 --out-dir ./out

# Stream CEF to localhost:514 at 2 events/sec (Ctrl-C to stop)
python3 ot_log_generator.py --stream --rate 2 \
    --syslog-host 127.0.0.1 --syslog-port 514 --syslog-proto udp

# Bounded stream — useful for cron-driven regression tests
timeout 30m python3 ot_log_generator.py --stream --rate 1 \
    --syslog-host 127.0.0.1 --syslog-port 514

# Reproducible output for unit tests
python3 ot_log_generator.py --count 50 --seed 42

# One platform only
python3 ot_log_generator.py --count 200 --platforms dragos
```

## Modes

**File mode** writes events to disk. Useful for parser development, posting JSON to a Log Ingestion API for testing custom tables, or eyeballing event shape:

```
out/
├── dragos.cef.log       # syslog-framed CEF lines
├── dragos.json          # array of REST API JSON objects
├── eyeinspect.cef.log
├── eyeinspect.json
├── eyesegment.cef.log
└── eyesegment.json
```

**Stream mode** emits continuously over syslog (UDP or TCP) or to stdout. This is what feeds Sentinel via the rsyslog → AMA pipeline.

## CLI reference

| Flag | Default | Purpose |
|------|---------|---------|
| `--count N` | 100 | Number of events for file mode |
| `--platforms ...` | all three | Subset of `dragos`, `eyeinspect`, `eyesegment` |
| `--format cef\|json\|both` | both | What file-mode formats to produce |
| `--out-dir DIR` | `./out` | Where file-mode writes |
| `--stream` | off | Switch to continuous emission mode |
| `--rate N` | 1.0 | Events per second in stream mode |
| `--syslog-host HOST` | - | If set with `--stream`, send via UDP/TCP syslog |
| `--syslog-port N` | 514 | Syslog port |
| `--syslog-proto udp\|tcp` | udp | Syslog transport |
| `--seed N` | - | RNG seed for reproducible output |

## Syslog framing

The generator emits **RFC 3164** framing (`<PRI>Mmm dd HH:MM:SS hostname CEF:0|...`). This matches what `logger --rfc3164` produces and is what rsyslog on Ubuntu (as configured by the Sentinel AMA installer) expects. Earlier versions used RFC 5424 framing, which caused rsyslog to mangle the message body — stripping whitespace and breaking CEF extension parsing. If you fork this and notice IPs landing in `AdditionalExtensions` instead of `SourceIP`/`DestinationIP`, that's the symptom.

## Event content notes

- **Dragos** events span ThreatBehavior, Modeling, Configuration, and Indicator analytic types. Some include a `worldviewActorId` matching real Dragos-named ICS threat groups (ELECTRUM, VOLTZITE, CHERNOVITE, KAMACITE, XENOTIME).
- **eyeInspect** events cover IndustrialThreatLibrary, BehavioralCheck, OperationalCheck, and CustomRule categories.
- **eyeSegment** events emit policy violations and changes across realistic OT zone pairs (`OT-L1-PLC`, `OT-L2-HMI`, `Engineering-DMZ`, `Corporate-FileShares`, `Internet`).
- All events carry **MITRE ATT&CK for ICS technique IDs** in `cs3` (e.g., T0836 Modify Parameter, T0843 Program Download, T0855 Unauthorized Command Message, T0858 Change Operating Mode).

## Extending the generator

The event templates live near the top of the file in `DRAGOS_NOTIFICATIONS`, `EYEINSPECT_ALERTS`, and `EYESEGMENT_VIOLATIONS`. To add a new rule, append a tuple in the matching format — the rest of the generator picks it up automatically.

To add a new platform entirely, write a `gen_<platform>_event()`, `render_<platform>_cef()`, and `render_<platform>_json()` triplet, then register them in the `PLATFORMS` dict near the bottom of the file.
