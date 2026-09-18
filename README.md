# Home SOC Lab: Suricata + Wazuh Network Intrusion Detection

A self-hosted, single-VM Security Operations Center (SOC) lab built on **Debian**, combining **Suricata** (network IDS) and **Wazuh** (SIEM/XDR) to monitor real home network traffic and surface security-relevant events on a live dashboard.

> Personal project, built for genuine home network monitoring and as a hands-on SOC/detection-engineering learning exercise. Designed, configured, and debugged the full pipeline end-to-end, including diagnosing and fixing a real Suricata/Wazuh integration bug.

## What it does

- **Captures live network traffic** on the host interface and inspects it against the Emerging Threats Open ruleset (50,000+ signatures) using Suricata, running in passive IDS mode
- **Ingests Suricata's alert output** into Wazuh, which parses, decodes, and indexes each event
- **Surfaces alerts on a searchable web dashboard** (Wazuh's OpenSearch-based UI), filterable by rule group, severity, source/destination IP, and signature
- **Self-monitors its own host** (the Wazuh manager acts as its own local agent) without requiring a separate agent installation
- **Runs headless and persistently** as a background VM, so monitoring continues without an active session

## Tech stack

| Layer | Technology |
|---|---|
| Host OS | Debian (minimal, headless, SSH-only) |
| Virtualization | VirtualBox (bridged networking) |
| Network IDS | Suricata 7.x |
| Ruleset | Emerging Threats Open (via `suricata-update`) |
| SIEM / log analysis | Wazuh 4.14 (manager, indexer, dashboard — all-in-one) |
| Log transport | Wazuh's built-in `localfile` log collector (JSON) |
| Dashboard | Wazuh's OpenSearch Dashboards-based web UI |

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │         Debian VM (headless)         │
                    │                                       │
  Home LAN traffic  │   ┌───────────┐      ┌────────────┐  │
 ─────────────────► │   │ Suricata  │─────►│  eve.json  │  │
   (bridged NIC)     │   │  (IDS)    │      │  (alerts)  │  │
                    │   └───────────┘      └─────┬──────┘  │
                    │                             │         │
                    │                             ▼         │
                    │                    ┌──────────────┐   │
                    │                    │Wazuh Manager │   │
                    │                    │ (self-agent, │   │
                    │                    │  no separate │   │
                    │                    │ agent needed)│   │
                    │                    └──────┬───────┘   │
                    │                           │           │
                    │                           ▼           │
                    │                  ┌─────────────────┐  │
                    │                  │ Wazuh Indexer +  │  │
                    │                  │    Dashboard     │  │
                    │                  └─────────────────┘  │
                    └─────────────────────────────────────┘
                                        │
                                        ▼
                          Browser on host machine
                        https://<vm-ip> (Wazuh UI)
```

## How it works

1. **Traffic capture**: Suricata runs in `af-packet` mode on the VM's bridged network interface, passively inspecting every packet against `HOME_NET` (scoped to the actual LAN subnet) and the loaded ruleset. No traffic is blocked or modified — detection only (IDS, not IPS).
2. **Alert generation**: Matches against the ruleset are written as structured JSON events to `/var/log/suricata/eve.json`, alongside flow, DNS, TLS, and stats telemetry.
3. **Log collection**: The Wazuh manager (configured via a `<localfile>` block in `/var/ossec/etc/ossec.conf`) tails `eve.json` directly, since the manager self-registers as its own local monitoring agent — no separate `wazuh-agent` package is installed on this host, avoiding a known packaging conflict where installing both on the same machine breaks the manager.
4. **Decoding and indexing**: Wazuh's built-in Suricata decoders/rules parse each JSON event into structured fields (signature, category, severity, source/destination IP and port) and forward them to the Wazuh indexer (OpenSearch) for storage and search.
5. **Visualization**: The Wazuh dashboard's **Threat Hunting → Events** view exposes all indexed alerts, filterable with `rule.groups: suricata` to isolate network-IDS events specifically, each shown with its rule level (severity), description, and source data.

## Setup

**1. Provision the VM**
Debian (minimal, SSH server only, no desktop), VirtualBox with a **bridged** network adapter (required so Suricata sees real LAN traffic, not NAT-translated traffic). 8 GB RAM / 4 vCPUs / 60 GB disk recommended for headroom on the Wazuh indexer.

**2. Install and configure Suricata**
```bash
sudo apt install suricata -y
```
- Set `HOME_NET` in `/etc/suricata/suricata.yaml` to the actual LAN subnet (e.g. `[192.168.1.0/24]`)
- Confirm the `af-packet` interface matches the VM's real NIC name (`ip a`)
- Disable `stats` events in the `eve-log` output block — see [Notes / limitations](#notes--limitations)
```bash
sudo suricata-update
sudo systemctl enable --now suricata
```

**3. Install Wazuh (manager, indexer, dashboard — no separate agent)**
```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a
```
> ⚠️ Do not install the separate `wazuh-agent` package on this same host. Both it and the manager use `/var/ossec`, and installing the agent afterward overwrites the manager's files and service registration. The manager already self-monitors as its own local agent (`000`).

**4. Wire Suricata into Wazuh**
Add to `/var/ossec/etc/ossec.conf`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```
```bash
sudo systemctl restart wazuh-manager
```

**5. Run headless, persistently**
```bash
VBoxManage startvm "soc-lab" --type headless
```
Access the dashboard from the host machine's browser at `https://<vm-ip>`.

## Notes / limitations

- **IDS, not IPS**: Suricata operates in passive detection mode only. It does not block or modify traffic — a deliberate choice to avoid making a home internet connection dependent on a single detection engine's availability.
- **Single sensor, host-level visibility**: Suricata watches only the VM's own interface, not the full home network. Extending to full-network visibility would mean placing the sensor on a SPAN/mirror port off the router's switch, or running it inline on the gateway itself — evaluated but not implemented here due to added complexity and risk to the router's primary routing function.
- **Decoder field-limit bug**: Wazuh's JSON decoder has a hard cap on fields per event (`analysisd.decoder_order_size`, default 256, max 1024). Suricata's `stats` event type — periodic internal engine telemetry, unrelated to actual detections — regularly exceeds this cap by a wide margin, causing `Too many fields for JSON decoder` errors. The commonly cited "official" fix (raising `decoder_order_size` to 1024) does not fully resolve this, as confirmed by multiple upstream GitHub issues. The actual fix applied here was identifying the offending event type via direct inspection of `eve.json` line lengths and disabling `stats` logging entirely in Suricata's `eve-log` output — since `stats` events carry no detection-relevant data, this has zero impact on alerting.
- **No adversarial traffic generation**: This is a personal monitoring setup, not a red-team/blue-team range — there is no attacker machine generating traffic to detect. Alerts reflect real (mostly benign) home network activity, occasionally flagging low-severity anomalies (e.g. TCP stream retransmissions from WiFi packet loss) rather than genuine attacks.
- **Single point of failure**: Everything (Suricata, Wazuh manager, indexer, dashboard) runs on one VM. A production deployment would separate these components and add redundancy.
