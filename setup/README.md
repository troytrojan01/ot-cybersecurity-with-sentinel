# Setup — Sentinel ingestion pipeline

End-to-end walkthrough for standing up the infrastructure that lets the generator's CEF events land in Sentinel's `CommonSecurityLog` table.

## Pipeline overview

```
generator → 127.0.0.1:514 → rsyslog → 127.0.0.1:28330 → AMA → DCR → Log Analytics → Sentinel
```

The simplest setup runs the generator on the same VM as rsyslog and AMA, so traffic to 514 stays on the loopback interface. No inbound NSG rules needed beyond Bastion.

## Prerequisites

- An Azure subscription where you can create resource groups, VNets, and VMs
- A Microsoft Sentinel workspace already enabled
- **Virtual Machine Contributor** and **Monitoring Contributor** roles (or owner of the resource group)

If your subscription is under strict Azure Landing Zone policies that deny VM creation patterns, the easiest workaround is to create a new management group under the tenant root and move a sandbox subscription into it. This isolates lab work from existing policy guardrails.

## Step 1 — Linux log forwarder VM

In the Azure portal:

- **Image:** Ubuntu Server 22.04 or 24.04 LTS
- **Size:** Standard_B2s (2 vCPU, 4 GB) is plenty
- **Authentication:** SSH key or password
- **Public inbound ports:** None (we'll use Bastion)
- **Public IP:** None
- **NSG:** create a basic one with no inbound rules from Internet

Once the VM is created, deploy Azure Bastion (Basic SKU is fine) in the same VNet. The subnet **must** be named exactly `AzureBastionSubnet` with at least a /26 prefix.

Connect via the VM's **Connect → Bastion** blade.

## Step 2 — Sentinel solution and DCR

In Sentinel:

1. **Content hub** → search "Common Event Format" → **Install**
2. **Configuration → Data connectors** → search "CEF" → open **Common Event Format (CEF) via AMA**
3. **Open connector page** → **+Create data collection rule**
4. **Basic** tab:
   - DCR name: `dcr-cef-ot-test`
   - Subscription and resource group: same as the VM
5. **Resources** tab: select your forwarder VM
6. **Collect** tab: select **LOG_INFO** as minimum level for all facilities (or at least `local0` and `local4`, which the generator uses)
7. **Review + create**

Azure auto-installs the Azure Monitor Agent on the selected VM. Wait 2–3 minutes.

## Step 3 — On the VM, configure rsyslog

SSH in via Bastion, then run Microsoft's installer script. It configures rsyslog to listen on 514 and forward to AMA on the local 28330 socket:

```bash
sudo wget -O Forwarder_AMA_installer.py \
  https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/Syslog/Forwarder_AMA_installer.py
sudo python3 Forwarder_AMA_installer.py
```

> **Note:** Ubuntu ships `python3`, not `python`. The original instructions use `python` — substitute `python3` or `sudo apt install python-is-python3` first.

Verify both listeners are up:

```bash
sudo ss -lnptu | grep -E ':(514|28330)\b'
# Expect:
#   rsyslog listening on 0.0.0.0:514 (udp and tcp)
#   mdsd    listening on 127.0.0.1:28330 (tcp)
```

Verify AMA service health:

```bash
sudo systemctl status azuremonitoragent.service     # should be active (running)
sudo systemctl status rsyslog.service               # should be active (running)
```

## Step 4 — Smoke test the pipe

Before running the generator, prove the pipeline works end-to-end with `logger`:

```bash
logger -p local4.warn -P 514 -n 127.0.0.1 --rfc3164 \
  -t CEF "0|Mock-test|MOCK|1.0|100|test event|3|src=1.2.3.4"
```

Wait 5–10 minutes, then query in Sentinel **Logs**:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(15m)
| where DeviceProduct == "MOCK"
```

If the row appears, the pipeline is good. If not, stop and troubleshoot here — adding the generator on top of a broken pipe makes diagnosis much harder.

## Step 5 — Run the generator

Copy `ot_log_generator.py` to the VM (paste via Bastion, or fetch via curl from a gist):

```bash
python3 ot_log_generator.py --stream --rate 2 \
    --syslog-host 127.0.0.1 --syslog-port 514 --syslog-proto udp
```

Watch traffic actually arrive at rsyslog:

```bash
sudo tcpdump -i lo -n port 514 -A -c 10
```

You should see CEF lines: `CEF:0|Dragos|Platform|...` and `CEF:0|Forescout|eyeInspect|...`.

## Step 6 — Verify in Sentinel

Give it 5–10 minutes from when the first events hit the VM. Then run:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(15m)
| where DeviceVendor in ("Dragos", "Forescout")
| summarize Events = count() by DeviceVendor, DeviceProduct, Activity
| order by Events desc
```

You should see Dragos Platform, Forescout eyeInspect, and Forescout eyeSegment events. From here, move on to the queries in `../queries/`.

## Troubleshooting

**No data after 15 minutes:**
1. `sudo tcpdump -i lo -n port 514` — are packets arriving? If not, the generator isn't sending.
2. `sudo tcpdump -i lo -n port 28330` — is rsyslog forwarding to AMA? If not, rsyslog config issue.
3. `tail -50 /var/opt/microsoft/azuremonitoragent/log/mdsd.err` — AMA error log.
4. Portal → DCR → confirm the VM appears under "Resources" and shows healthy.

**Events arrive in `Syslog` table instead of `CommonSecurityLog`:**
The DCR's `streams` field is set to `Microsoft-Syslog` instead of `Microsoft-CommonSecurityLog`. Delete and recreate the DCR via the **CEF via AMA** connector page (not the **Syslog via AMA** page).

**`SourceIP`/`DestinationIP` empty, IPs concatenated in `AdditionalExtensions`:**
The generator is emitting RFC 5424 framing instead of RFC 3164. Make sure you're running the current version of `ot_log_generator.py` (look for `_now_rfc3164` in the source).

**Cost creeping up:**
At `--rate 2` the generator produces about 170 MB of ingestion per day. Use `timeout 30m python3 ot_log_generator.py ...` for bounded test runs, or delete the entire resource group when done.

## Cleanup

When finished with the lab:

```bash
az group delete --name "<your-resource-group>" --yes --no-wait
```

This removes the VM, NICs, Bastion, public IPs, and any orphaned disks in one shot. Generator events already ingested into the workspace stay there until your retention policy ages them out — or you can purge them via the Log Analytics purge API filtered to `DeviceVendor in ("Dragos", "Forescout")`.
