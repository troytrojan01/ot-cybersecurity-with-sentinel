# CEF → CommonSecurityLog field mapping

How CEF extension keys emitted by the generator land in Sentinel's `CommonSecurityLog` table. Useful when writing queries — the column name in KQL is rarely identical to the CEF key on the wire.

## Standard CEF fields

| CEF wire format | `CommonSecurityLog` column | Notes |
|-----------------|---------------------------|-------|
| Device Vendor (header) | `DeviceVendor` | "Dragos", "Forescout" |
| Device Product (header) | `DeviceProduct` | "Platform", "eyeInspect", "eyeSegment" |
| Device Version (header) | `DeviceVersion` | "2.3", "5.4.0", "2.7.1" |
| Signature ID (header) | `DeviceEventClassID` | The rule ID — "MOD-001", "ITL-2034", "POLVIO-1042" |
| Event Name (header) | **`Activity`** | This is what trips most people up — not `Name` |
| Severity (header) | `LogSeverity` | 0–10 scale |
| `src=` | `SourceIP` | |
| `dst=` | `DestinationIP` | |
| `spt=` | `SourcePort` | |
| `dpt=` | `DestinationPort` | |
| `proto=` | `Protocol` | TCP, UDP |
| `msg=` | `Message` | Human-readable summary |
| `externalId=` | `ExternalID` | The alert/event ID from the source system |
| `deviceProcessName=` | `DeviceProcessName` | eyeInspect uses this for engineering tool (Studio5000, RSLogix5000) |

## Custom string fields

CEF allows six `csN` slots that vendors can assign to anything. Each has a paired `csNLabel` that tells you what the value represents.

### Dragos Platform

| Slot | Label | Value examples |
|------|-------|----------------|
| `cs1` | `AssetRole` | EngineeringWorkstation, HMI, Historian, JumpHost |
| `cs2` | `DestRole` | PLC, RTU, IED, SafetyController, DCSController |
| `cs3` | `MitreIcsTechnique` | T0836, T0843, T0855, T0858, T0859, T0812, T0813, T0846 |
| `cs4` | `Analytic` | ThreatBehavior, Modeling, Configuration, Indicator |

### Forescout eyeInspect

| Slot | Label | Value examples |
|------|-------|----------------|
| `cs1` | `Protocol` | Modbus/TCP, S7comm, EtherNet/IP, OPC UA, DNP3, IEC-104 |
| `cs2` | `DstAssetRole` | PLC, RTU, SafetyController |
| `cs3` | `SrcAssetRole` | EngineeringStation, HMI, JumpHost |
| `cs4` | `RuleCategory` | IndustrialThreatLibrary, BehavioralCheck, OperationalCheck, CustomRule |
| `cn1` | `AlertSeverityNum` | Numeric severity (1–10) for ordering |

### Forescout eyeSegment

| Slot | Label | Value examples |
|------|-------|----------------|
| `cs1` | `SrcZone` | OT-L1-PLC, OT-L2-HMI, Engineering-DMZ |
| `cs2` | `DstZone` | OT-L1-PLC, Corporate-FileShares, Internet |
| `cs3` | `PolicyName` | Block-OT-to-Corp-SMB, Block-OT-Internet-Outbound, Restrict-DMZ-to-L1 |
| `cs4` | `Action` | Alert, Block, Audit |

## Fields that land in `AdditionalExtensions`

CEF extension keys that don't match a standard Sentinel column get dumped into `AdditionalExtensions` as one big string: `key1=value1; key2=value2;`. Pull them out with `extract()` or `parse_csv()`.

### Dragos

| Key | What it is |
|-----|------------|
| `dragosCaseId` | Case grouping for related notifications (`CASE-2026-0526-324`) |
| `dragosNotifId` | Unique notification ID (`NOTIF-90070`) |
| `worldviewActorId` | When present: named ICS threat group (ELECTRUM, VOLTZITE, CHERNOVITE, KAMACITE, XENOTIME). Indicates an indicator-match against Dragos WorldView intel. |

### eyeInspect

The standard fields cover most of it. The pcap-available flag and sensor ID end up in `AdditionalExtensions` in the JSON-side schema but aren't emitted in CEF by this generator.

### eyeSegment

The standard fields cover everything; no custom extensions used.

## Worked example

CEF on the wire:

```
<134>May 26 13:09:00 dragos-sitestore CEF:0|Dragos|Platform|2.3|WV-204|Indicator Match — WorldView ELECTRUM Infrastructure|9|src=10.21.4.47 dst=185.244.25.18 spt=51234 dpt=443 proto=TCP cs1Label=AssetRole cs1=EngineeringWorkstation cs2Label=DestRole cs2=PLC cs3Label=MitreIcsTechnique cs3=T0859 cs4Label=Analytic cs4=Indicator msg=Outbound connection to IP listed in WorldView ELECTRUM infrastructure feed dragosCaseId=CASE-2026-0526-321 dragosNotifId=NOTIF-90021 worldviewActorId=ELECTRUM
```

In `CommonSecurityLog`:

| Column | Value |
|--------|-------|
| `DeviceVendor` | Dragos |
| `DeviceProduct` | Platform |
| `DeviceVersion` | 2.3 |
| `DeviceEventClassID` | WV-204 |
| `Activity` | Indicator Match — WorldView ELECTRUM Infrastructure |
| `LogSeverity` | 9 |
| `SourceIP` | 10.21.4.47 |
| `DestinationIP` | 185.244.25.18 |
| `SourcePort` | 51234 |
| `DestinationPort` | 443 |
| `Protocol` | TCP |
| `DeviceCustomString1` | EngineeringWorkstation |
| `DeviceCustomString1Label` | AssetRole |
| `DeviceCustomString2` | PLC |
| `DeviceCustomString2Label` | DestRole |
| `DeviceCustomString3` | T0859 |
| `DeviceCustomString3Label` | MitreIcsTechnique |
| `DeviceCustomString4` | Indicator |
| `DeviceCustomString4Label` | Analytic |
| `Message` | Outbound connection to IP listed in WorldView ELECTRUM infrastructure feed |
| `AdditionalExtensions` | `dragosCaseId=CASE-2026-0526-321;dragosNotifId=NOTIF-90021;worldviewActorId=ELECTRUM` |
