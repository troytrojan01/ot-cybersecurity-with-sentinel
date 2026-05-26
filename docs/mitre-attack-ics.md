# MITRE ATT&CK for ICS — techniques used in this lab

The generator emits MITRE ATT&CK for ICS technique IDs in `DeviceCustomString3` (Dragos) and `DeviceCustomString3`/`DeviceCustomString4` (eyeInspect, depending on rule). Below is the subset of techniques the generator references, with what they mean and which generated rules trigger them. This is a quick-reference companion to the queries in `../queries/`.

For the full framework, see [attack.mitre.org/matrices/ics](https://attack.mitre.org/matrices/ics/).

## Techniques in this lab

| ID | Name | Tactic | What it looks like in OT |
|----|------|--------|--------------------------|
| **T0812** | Default Credentials | Initial Access | Adversary uses out-of-the-box admin creds. Generator emits this as cleartext-credential observations (`CFG-022`, `ITL-1880`). |
| **T0813** | Denial of Control | Inhibit Response Function | An operator loses the ability to direct the process — e.g., S7 Stop-CPU command (`S7-077`). |
| **T0836** | Modify Parameter | Impair Process Control | Writing a new setpoint or tuning value to a controller. Triggered by `MOD-001` Modbus FC16 writes and `CUS-0007` custom safety-controller writes. |
| **T0843** | Program Download | Lateral Movement / Persistence | Pushing a new control program (ladder logic, structured text) to a PLC. Triggered by `ENI-014` and `ITL-2034`. |
| **T0846** | Remote System Discovery | Discovery | Enumerating other OT devices — e.g., IEC-104 general interrogation from an unknown master (`IEC-051`). |
| **T0855** | Unauthorized Command Message | Inhibit Response Function | Issuing protocol commands outside the normal baseline. `MOD-118` anomalous Modbus FC sequence. |
| **T0858** | Change Operating Mode | Impair Process Control | Switching a PLC from RUN to PROGRAM mode, which halts process control. `ITL-2101`. |
| **T0859** | Valid Accounts | Lateral Movement | Off-hours activity on engineering stations (`BHV-0512`); WorldView IOC match on actor infrastructure (`WV-204`). |
| **T0888** | Remote Services | Lateral Movement | New communication pair observed outside baseline (`BHV-0420`). |

## Why these specifically

The selection prioritizes techniques that:

1. **Produce telemetry visible on the wire** — generator events stem from network-observable behaviors that a Dragos or Forescout sensor would actually see, not host-based artifacts.
2. **Map to high-impact OT scenarios** — program downloads, mode changes, and unauthorized control messages are the small set of techniques that directly threaten process safety.
3. **Span multiple tactics** — discovery, lateral movement, impair-process-control, and inhibit-response-function are all represented, so detection coverage can be measured.

## Coverage gaps worth knowing

Techniques the generator does **not** emit, but a real environment would also need:

- **T0865** Spearphishing Attachment — typically an IT-side telemetry source (Defender for Office)
- **T0820** Exploitation for Evasion — needs deep packet inspection beyond what most CEF feeds carry
- **T0830** Adversary-in-the-Middle — usually inferred from anomaly chains, not emitted as a discrete event
- **T0809** Data Destruction — host-side; not visible on OT network sensors

If you extend the generator (see `../generator/README.md`), these are good candidates for new event templates.
