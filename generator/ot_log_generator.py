#!/usr/bin/env python3
"""
ot_log_generator.py — Synthetic OT security telemetry generator

Produces realistic sample logs in the formats described in the
OT_Security_Microsoft_Integration_Report:

  - Dragos Platform:    CEF Syslog + REST API JSON notifications
  - Forescout eyeInspect:   CEF Syslog + REST API JSON alerts
  - Forescout eyeSegment:   CEF Syslog policy-violation events

Output modes:
  - file    : write CEF lines and/or JSON to files on disk
  - stdout  : print CEF lines to stdout (pipe into rsyslog/logger)
  - syslog  : send CEF lines over UDP/TCP to a syslog collector

Usage examples:
  # Generate a mixed batch of 500 events to ./out/
  python ot_log_generator.py --count 500 --out-dir ./out

  # Stream CEF to stdout at ~5 events/sec (Ctrl-C to stop)
  python ot_log_generator.py --stream --rate 5 --format cef

  # Send CEF over UDP to a syslog collector on 514
  python ot_log_generator.py --stream --rate 2 \
      --syslog-host 10.0.0.50 --syslog-port 514 --syslog-proto udp
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# ---------------------------------------------------------------------------
# Reference data — kept aligned with the uploaded report
# ---------------------------------------------------------------------------

OT_SUBNETS = [
    ("10.21.4.0/24",  "Plant-A-L2"),
    ("10.30.7.0/24",  "Plant-B-L2"),
    ("10.40.2.0/24",  "Plant-C-L1"),
    ("10.50.5.0/24",  "Corporate-FileShares"),
    ("10.60.9.0/24",  "Engineering-DMZ"),
]

ASSET_ROLES_SRC = [
    "EngineeringWorkstation",
    "EngineeringStation",
    "HMI",
    "Historian",
    "JumpHost",
]

ASSET_ROLES_DST = [
    "PLC",
    "RTU",
    "IED",
    "SafetyController",
    "DCSController",
]

VENDORS = ["Rockwell", "Schneider", "Siemens", "ABB", "Honeywell", "Emerson", "Yokogawa"]

PLC_MODELS = {
    "Rockwell":  ["ControlLogix 5580", "CompactLogix 5380", "MicroLogix 1400"],
    "Schneider": ["Modicon M580", "Modicon M340", "Quantum 140"],
    "Siemens":   ["S7-1500", "S7-1200", "S7-400"],
    "ABB":       ["AC500-eCo", "AC800M"],
    "Honeywell": ["ControlEdge PLC", "Experion C300"],
    "Emerson":   ["DeltaV M-Series", "DeltaV S-Series"],
    "Yokogawa":  ["FCN-RTU", "Vnet/IP FCS"],
}

PROTOCOLS = [
    ("Modbus/TCP",   502,   "TCP"),
    ("EtherNet/IP",  44818, "TCP"),
    ("S7comm",       102,   "TCP"),
    ("DNP3",         20000, "TCP"),
    ("IEC-104",      2404,  "TCP"),
    ("OPC UA",       4840,  "TCP"),
    ("BACnet",       47808, "UDP"),
]

# (rule_id, title, mitre_ics_techs, analytic, severity_1_10, summary)
DRAGOS_NOTIFICATIONS = [
    ("MOD-001", "Unauthorized Modbus Write Detected",
     ["T0836", "T0855"], "ThreatBehavior", 7,
     "Engineering workstation issued unsolicited Modbus FC16 write to PLC outside maintenance window"),
    ("ENI-014", "Unauthorized PLC Program Download",
     ["T0843"], "ThreatBehavior", 8,
     "Project file download to controller from non-approved engineering host"),
    ("CFG-022", "Cleartext Credentials Observed in OT Protocol",
     ["T0812"], "Configuration", 5,
     "Cleartext credentials observed in Telnet session to field device"),
    ("MOD-118", "Anomalous Modbus Function Code Sequence",
     ["T0855"], "Modeling", 6,
     "Modbus function code pattern deviates from established baseline for this asset pair"),
    ("WV-204",  "Indicator Match — WorldView ELECTRUM Infrastructure",
     ["T0859"], "Indicator", 9,
     "Outbound connection to IP listed in WorldView ELECTRUM infrastructure feed"),
    ("S7-077",  "S7 Stop CPU Command Observed",
     ["T0813"], "ThreatBehavior", 9,
     "S7comm Stop-CPU function issued to PLC from non-approved host"),
    ("IEC-051", "IEC-104 Interrogation Command from Unknown Master",
     ["T0846"], "ThreatBehavior", 6,
     "IEC-104 general interrogation command observed from previously unseen master station"),
]

WORLDVIEW_ACTORS = ["ELECTRUM", "VOLTZITE", "CHERNOVITE", "KAMACITE", "XENOTIME", None, None, None]

# (rule_id, title, rule_category, mitre_ics, severity_label, severity_num, summary, eng_tool)
EYEINSPECT_ALERTS = [
    ("ITL-2034", "Unauthorized PLC Program Download",
     "IndustrialThreatLibrary", ["T0843"], "High", 8,
     "Program download to PLC outside approved change window", "RSLogix5000"),
    ("ITL-2101", "PLC Mode Change to Program",
     "IndustrialThreatLibrary", ["T0858"], "Critical", 10,
     "PLC mode change to PROGRAM observed from engineering workstation", "Studio5000"),
    ("BHV-0420", "New Communication Pair Outside Baseline",
     "BehavioralCheck", ["T0888"], "Medium", 5,
     "Source asset initiated EtherNet/IP session with destination never observed before", None),
    ("OPS-115",  "Setpoint Outside Engineering Limits",
     "OperationalCheck", ["T0836"], "High", 8,
     "Setpoint write value falls outside configured engineering limits for tag", None),
    ("ITL-1880", "Insecure Service Detected on PLC",
     "IndustrialThreatLibrary", ["T0812"], "Low", 3,
     "Telnet service responding on PLC management port", None),
    ("BHV-0512", "Off-Hours Activity on Engineering Station",
     "BehavioralCheck", ["T0859"], "Medium", 6,
     "Engineering station activity observed outside business hours window", None),
    ("CUS-0007", "Custom Rule: Modbus FC16 to Safety Controller",
     "CustomRule", ["T0836"], "Critical", 9,
     "Custom site rule triggered: Modbus FC16 write to asset tagged Safety", None),
]

# (rule_id, title, src_zone, dst_zone, policy_name, action, severity, summary)
EYESEGMENT_VIOLATIONS = [
    ("POLVIO-1009", "Segmentation Policy Violation",
     "OT-L1-PLC", "Corporate-FileShares", "Block-OT-to-Corp-SMB", "Alert", 6,
     "Traffic from OT Level 1 PLC zone to Corporate file share zone violates active segmentation policy"),
    ("POLVIO-1042", "Segmentation Policy Violation",
     "OT-L2-HMI", "Internet", "Block-OT-Internet-Outbound", "Block", 8,
     "Outbound internet traffic from OT Level 2 HMI zone blocked by segmentation policy"),
    ("POLVIO-1108", "Segmentation Policy Violation",
     "Engineering-DMZ", "OT-L1-PLC", "Restrict-DMZ-to-L1", "Alert", 5,
     "Unapproved protocol observed from Engineering DMZ to OT Level 1"),
    ("POLVIO-1201", "Segmentation Policy Change",
     "n/a", "n/a", "Audit", "Audit", 3,
     "Segmentation policy modified by administrator"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso(jitter_minutes: int = 0) -> str:
    """Return current UTC timestamp (RFC 3339), optionally jittered backward."""
    delta = random.randint(0, jitter_minutes * 60) if jitter_minutes else 0
    ts = datetime.now(timezone.utc).timestamp() - delta
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_rfc3164(jitter_minutes: int = 0) -> str:
    """Return current timestamp in RFC 3164 format: 'Mmm dd HH:MM:SS' (local time).

    rsyslog parses this format reliably; ISO/RFC 5424 timestamps can be mangled
    by the daemon when it normalizes messages before forwarding to AMA.
    """
    delta = random.randint(0, jitter_minutes * 60) if jitter_minutes else 0
    ts = datetime.now().timestamp() - delta
    # %e gives space-padded day per RFC 3164; not portable on all platforms,
    # so build it manually.
    dt = datetime.fromtimestamp(ts)
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"


def _rand_ip_from_subnet(subnet: str) -> str:
    """Crude random host in a /24."""
    base = subnet.split("/")[0].rsplit(".", 1)[0]
    return f"{base}.{random.randint(2, 250)}"


def _rand_ot_endpoint(role_pool: list[str]) -> tuple[str, str, str]:
    """Pick a (subnet_zone, ip, role) tuple from one of the OT subnets."""
    subnet, zone = random.choice(OT_SUBNETS[:3])  # Plants only
    return zone, _rand_ip_from_subnet(subnet), random.choice(role_pool)


def _rand_vendor_model() -> tuple[str, str, str]:
    vendor = random.choice(VENDORS)
    model = random.choice(PLC_MODELS[vendor])
    firmware = f"{random.randint(20, 35)}.{random.randint(0, 20):03d}"
    return vendor, model, firmware


def _cef_escape(value: str) -> str:
    """Escape pipes and backslashes in CEF extensions per the spec."""
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


# ---------------------------------------------------------------------------
# Dragos generators
# ---------------------------------------------------------------------------

def gen_dragos_event() -> dict:
    """Build a structured event we can render as either CEF or JSON."""
    rule_id, title, mitre, analytic, severity, summary = random.choice(DRAGOS_NOTIFICATIONS)
    _, src_ip, src_role = _rand_ot_endpoint(ASSET_ROLES_SRC)
    _, dst_ip, dst_role = _rand_ot_endpoint(ASSET_ROLES_DST)
    proto_name, dst_port, transport = random.choice(PROTOCOLS)
    src_vendor, _, _ = _rand_vendor_model()
    dst_vendor, dst_model, dst_fw = _rand_vendor_model()
    case_seq = random.randint(1, 999)
    notif_seq = random.randint(10000, 99999)
    actor = random.choice(WORLDVIEW_ACTORS)
    ts = _now_iso(jitter_minutes=120)

    return {
        "rule_id": rule_id,
        "title": title,
        "summary": summary,
        "mitre_ics": mitre,
        "analytic": analytic,
        "severity": severity,
        "timestamp": ts,
        "src": {"ip": src_ip, "role": src_role, "vendor": src_vendor,
                "asset_id": f"ASSET-{src_role[:3].upper()}-{random.randint(1, 99):02d}"},
        "dst": {"ip": dst_ip, "role": dst_role, "vendor": dst_vendor,
                "model": dst_model, "firmware": dst_fw,
                "asset_id": f"ASSET-{dst_role[:3].upper()}-{random.randint(1, 99):02d}"},
        "src_port": random.randint(40000, 60000),
        "dst_port": dst_port,
        "protocol": proto_name,
        "transport": transport,
        "case_id": f"CASE-{datetime.now().strftime('%Y-%m%d')}-{case_seq:03d}",
        "notif_id": f"NOTIF-{notif_seq}",
        "worldview_actor": actor,
    }


def render_dragos_cef(ev: dict) -> str:
    """Render Dragos event as a CEF Syslog line matching the report's sample."""
    cef_header = (
        f"CEF:0|Dragos|Platform|2.3|{ev['rule_id']}|{ev['title']}|{ev['severity']}|"
    )
    parts = [
        f"src={ev['src']['ip']}",
        f"dst={ev['dst']['ip']}",
        f"spt={ev['src_port']}",
        f"dpt={ev['dst_port']}",
        f"proto={ev['transport']}",
        f"cs1Label=AssetRole cs1={ev['src']['role']}",
        f"cs2Label=DestRole cs2={ev['dst']['role']}",
        f"cs3Label=MitreIcsTechnique cs3={','.join(ev['mitre_ics'])}",
        f"cs4Label=Analytic cs4={ev['analytic']}",
        f"msg={_cef_escape(ev['summary'])}",
        f"dragosCaseId={ev['case_id']}",
        f"dragosNotifId={ev['notif_id']}",
    ]
    if ev["worldview_actor"]:
        parts.append(f"worldviewActorId={ev['worldview_actor']}")
    syslog_pri = "<134>"  # local0.info; RFC 3164 (no version digit)
    return f"{syslog_pri}{_now_rfc3164()} dragos-sitestore {cef_header}{' '.join(parts)}"


def render_dragos_json(ev: dict) -> dict:
    """Render Dragos event as REST API JSON matching the report's sample."""
    return {
        "id": ev["notif_id"],
        "created": ev["timestamp"].replace("Z", ".000Z"),
        "severity": ev["severity"],
        "type": {"ThreatBehavior": "threat_behavior",
                 "Modeling": "modeling",
                 "Configuration": "configuration",
                 "Indicator": "indicator"}[ev["analytic"]],
        "title": ev["title"],
        "summary": ev["summary"],
        "mitre_ics": ev["mitre_ics"],
        "source": ev["src"],
        "destination": ev["dst"],
        "protocol": ev["protocol"],
        "case_id": ev["case_id"],
        "worldview_actor": ev["worldview_actor"],
        "pcap_uri": f"/api/v2/pcap/{ev['notif_id']}.pcap",
    }


# ---------------------------------------------------------------------------
# Forescout eyeInspect generators
# ---------------------------------------------------------------------------

def gen_eyeinspect_event() -> dict:
    rule_id, title, category, mitre, sev_label, sev_num, summary, eng_tool = random.choice(EYEINSPECT_ALERTS)
    _, src_ip, src_role = _rand_ot_endpoint(ASSET_ROLES_SRC)
    _, dst_ip, dst_role = _rand_ot_endpoint(ASSET_ROLES_DST)
    proto_name, dst_port, transport = random.choice(PROTOCOLS)
    src_vendor, _, _ = _rand_vendor_model()
    dst_vendor, dst_model, dst_fw = _rand_vendor_model()
    ts = _now_iso(jitter_minutes=120)

    return {
        "rule_id": rule_id,
        "title": title,
        "rule_category": category,
        "mitre_ics": mitre,
        "severity_label": sev_label,
        "severity_num": sev_num,
        "summary": summary,
        "engineering_tool": eng_tool,
        "timestamp": ts,
        "src": {"ip": src_ip, "role": src_role, "vendor": src_vendor, "os": "Windows 10"},
        "dst": {"ip": dst_ip, "role": dst_role, "vendor": dst_vendor,
                "model": dst_model, "firmware": dst_fw},
        "src_port": random.randint(40000, 60000),
        "dst_port": dst_port,
        "protocol": proto_name,
        "transport": transport,
        "alert_id": random.randint(500000, 999999),
        "sensor_id": f"SENSOR-PLT-{random.choice(['A', 'B', 'C'])}-{random.randint(1, 9):02d}",
    }


def render_eyeinspect_cef(ev: dict) -> str:
    cef_header = (
        f"CEF:0|Forescout|eyeInspect|5.4.0|{ev['rule_id']}|{ev['title']}|{ev['severity_num']}|"
    )
    parts = [
        f"src={ev['src']['ip']}",
        f"dst={ev['dst']['ip']}",
        f"spt={ev['src_port']}",
        f"dpt={ev['dst_port']}",
        f"proto={ev['transport']}",
        f"cs1Label=Protocol cs1={ev['protocol']}",
        f"cs2Label=DstAssetRole cs2={ev['dst']['role']}",
        f"cs3Label=SrcAssetRole cs3={ev['src']['role']}",
        f"cs4Label=RuleCategory cs4={ev['rule_category']}",
        f"cn1Label=AlertSeverityNum cn1={ev['severity_num']}",
        f"msg={_cef_escape(ev['summary'])}",
        f"externalId=ALERT-{ev['alert_id']}",
    ]
    if ev["engineering_tool"]:
        parts.append(f"deviceProcessName={ev['engineering_tool']}")
    syslog_pri = "<132>"
    return f"{syslog_pri}{_now_rfc3164()} eyeinspect-cc {cef_header}{' '.join(parts)}"


def render_eyeinspect_json(ev: dict) -> dict:
    return {
        "alert_id": ev["alert_id"],
        "timestamp": ev["timestamp"],
        "severity": ev["severity_label"],
        "rule_id": ev["rule_id"],
        "rule_category": ev["rule_category"],
        "title": ev["title"],
        "src_ip": ev["src"]["ip"],
        "dst_ip": ev["dst"]["ip"],
        "protocol": ev["protocol"],
        "src_asset": ev["src"],
        "dst_asset": ev["dst"],
        "mitre_attack_ics": ev["mitre_ics"],
        "pcap_available": True,
        "sensor_id": ev["sensor_id"],
    }


# ---------------------------------------------------------------------------
# Forescout eyeSegment generators
# ---------------------------------------------------------------------------

def gen_eyesegment_event() -> dict:
    rule_id, title, src_zone, dst_zone, policy, action, severity, summary = random.choice(EYESEGMENT_VIOLATIONS)
    src_ip = _rand_ip_from_subnet(random.choice(OT_SUBNETS)[0])
    dst_ip = _rand_ip_from_subnet(random.choice(OT_SUBNETS)[0])
    proto_name, dst_port, transport = random.choice(PROTOCOLS)
    return {
        "rule_id": rule_id,
        "title": title,
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "policy_name": policy,
        "action": action,
        "severity": severity,
        "summary": summary,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(40000, 60000),
        "dst_port": dst_port,
        "transport": transport,
        "protocol": proto_name,
        "timestamp": _now_iso(jitter_minutes=120),
        "event_id": f"POL-EVT-{random.randint(100000, 999999)}",
    }


def render_eyesegment_cef(ev: dict) -> str:
    cef_header = (
        f"CEF:0|Forescout|eyeSegment|2.7.1|{ev['rule_id']}|{ev['title']}|{ev['severity']}|"
    )
    parts = [
        f"src={ev['src_ip']}",
        f"dst={ev['dst_ip']}",
        f"spt={ev['src_port']}",
        f"dpt={ev['dst_port']}",
        f"proto={ev['transport']}",
        f"cs1Label=SrcZone cs1={ev['src_zone']}",
        f"cs2Label=DstZone cs2={ev['dst_zone']}",
        f"cs3Label=PolicyName cs3={ev['policy_name']}",
        f"cs4Label=Action cs4={ev['action']}",
        f"msg={_cef_escape(ev['summary'])}",
        f"externalId={ev['event_id']}",
    ]
    syslog_pri = "<134>"
    return f"{syslog_pri}{_now_rfc3164()} forescout-platform {cef_header}{' '.join(parts)}"


def render_eyesegment_json(ev: dict) -> dict:
    return {
        "event_id": ev["event_id"],
        "timestamp": ev["timestamp"],
        "severity": ev["severity"],
        "rule_id": ev["rule_id"],
        "title": ev["title"],
        "src_zone": ev["src_zone"],
        "dst_zone": ev["dst_zone"],
        "policy_name": ev["policy_name"],
        "action": ev["action"],
        "src_ip": ev["src_ip"],
        "dst_ip": ev["dst_ip"],
        "protocol": ev["protocol"],
        "summary": ev["summary"],
    }


# ---------------------------------------------------------------------------
# Dispatch & emission
# ---------------------------------------------------------------------------

PLATFORMS = {
    "dragos":     (gen_dragos_event,     render_dragos_cef,     render_dragos_json),
    "eyeinspect": (gen_eyeinspect_event, render_eyeinspect_cef, render_eyeinspect_json),
    "eyesegment": (gen_eyesegment_event, render_eyesegment_cef, render_eyesegment_json),
}


def make_event(platform: str) -> tuple[dict, str, dict]:
    gen, cef_fn, json_fn = PLATFORMS[platform]
    raw = gen()
    return raw, cef_fn(raw), json_fn(raw)


@dataclass
class SyslogSink:
    host: str
    port: int
    proto: str  # 'udp' or 'tcp'
    sock: socket.socket | None = None

    def connect(self) -> None:
        family = socket.AF_INET
        if self.proto == "udp":
            self.sock = socket.socket(family, socket.SOCK_DGRAM)
        else:
            self.sock = socket.socket(family, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))

    def send(self, line: str) -> None:
        assert self.sock is not None
        data = (line + "\n").encode("utf-8")
        if self.proto == "udp":
            self.sock.sendto(data, (self.host, self.port))
        else:
            self.sock.sendall(data)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description="Generate synthetic Dragos / Forescout OT security logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--count", type=int, default=100,
                   help="Number of events to generate (ignored in --stream mode)")
    p.add_argument("--platforms", nargs="+", default=["dragos", "eyeinspect", "eyesegment"],
                   choices=list(PLATFORMS.keys()),
                   help="Which platforms to generate events for")
    p.add_argument("--format", choices=["cef", "json", "both"], default="both",
                   help="Output format(s) for file mode")
    p.add_argument("--out-dir", type=str, default="./out",
                   help="Directory for file-mode output")
    p.add_argument("--stream", action="store_true",
                   help="Stream events continuously (stdout or syslog), ignore --count")
    p.add_argument("--rate", type=float, default=1.0,
                   help="Events per second in --stream mode")
    p.add_argument("--syslog-host", type=str,
                   help="If set with --stream, send CEF over syslog to this host")
    p.add_argument("--syslog-port", type=int, default=514)
    p.add_argument("--syslog-proto", choices=["udp", "tcp"], default="udp")
    p.add_argument("--seed", type=int, help="Seed RNG for reproducible output")
    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    # ----- Stream mode -----
    if args.stream:
        sink: SyslogSink | None = None
        if args.syslog_host:
            sink = SyslogSink(args.syslog_host, args.syslog_port, args.syslog_proto)
            try:
                sink.connect()
            except OSError as e:
                print(f"Failed to connect to syslog at {args.syslog_host}:{args.syslog_port}: {e}",
                      file=sys.stderr)
                return 1
            print(f"Streaming CEF to {args.syslog_host}:{args.syslog_port}/{args.syslog_proto} "
                  f"at {args.rate} eps. Ctrl-C to stop.", file=sys.stderr)
        else:
            print(f"Streaming CEF to stdout at {args.rate} eps. Ctrl-C to stop.", file=sys.stderr)

        interval = 1.0 / args.rate if args.rate > 0 else 0
        try:
            while True:
                platform = random.choice(args.platforms)
                _, cef_line, _ = make_event(platform)
                if sink:
                    sink.send(cef_line)
                else:
                    print(cef_line, flush=True)
                if interval:
                    time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopped.", file=sys.stderr)
            return 0

    # ----- File mode -----
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cef_handles: dict[str, object] = {}
    json_buffers: dict[str, list] = {}

    if args.format in ("cef", "both"):
        for pf in args.platforms:
            cef_handles[pf] = open(out_dir / f"{pf}.cef.log", "w", encoding="utf-8")
    if args.format in ("json", "both"):
        for pf in args.platforms:
            json_buffers[pf] = []

    try:
        for _ in range(args.count):
            platform = random.choice(args.platforms)
            _, cef_line, json_obj = make_event(platform)
            if platform in cef_handles:
                cef_handles[platform].write(cef_line + "\n")
            if platform in json_buffers:
                json_buffers[platform].append(json_obj)
    finally:
        for h in cef_handles.values():
            h.close()

    for pf, buf in json_buffers.items():
        with open(out_dir / f"{pf}.json", "w", encoding="utf-8") as f:
            json.dump(buf, f, indent=2, default=str)

    print(f"Generated {args.count} events across {args.platforms} into {out_dir}/", file=sys.stderr)
    for pf in args.platforms:
        if pf in cef_handles:
            print(f"  - {out_dir}/{pf}.cef.log", file=sys.stderr)
        if pf in json_buffers:
            print(f"  - {out_dir}/{pf}.json   ({len(json_buffers[pf])} events)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
