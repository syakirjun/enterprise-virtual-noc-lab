# enterprise-virtual-noc-lab
Multi-tier virtual enterprise network with OPNsense, Windows Server AD DS, VLAN routing, and NOC packet triage.

# Enterprise Virtual Network & NOC Incident Lab

**Author:** syakirjun   
**Environment:** Debian 12 Hypervisor, VirtualBox, OPNsense 24.x, Windows Server 2022 (AD DS & DNS), Windows 11 Pro, Kali Linux  

---

## 1. Executive Summary & Architecture
This project demonstrates the design, deployment, and operational troubleshooting of an enterprise-grade virtual network. The environment features multi-tier VLAN segmentation routed through an OPNsense edge firewall, an Active Directory domain infrastructure (`pmm.edu`), isolated security auditing endpoints, and deep-packet inspection (DPI) analysis for Layer 2 through Layer 4 fault triage.

### Network Topology
```text
                          [ Public Internet / Home Uplink ]
                                         │ (NAT)
                          ┌──────────────┴──────────────┐
                          │   OPNsense Edge Firewall    │
                          │   (Multi-Interface Core)    │
                          └───────┬──────┬──────┬───────┘
                                  │      │      │
          ┌───────────────────────┘      │      └───────────────────────┐
          │ (vlan10-corp)                │ (vlan20-servers)             │ (vlan30-security)
          ▼                              ▼                              ▼
┌──────────────────┐           ┌────────────────────┐         ┌──────────────────┐
│ Windows 11 Pro   │           │ Windows Server 2022│         │ Kali Linux       │
│ Corporate Client │           │ Domain Controller  │         │ Security Testing │
│ 10.10.10.50/24   │           │ (MY-DC-01.pmm.edu) │         │ 10.10.30.50/24   │
│ Gateway: .1      │           │ 10.10.20.10/24     │         │ Gateway: .1      │
└──────────────────┘           └────────────────────┘         └──────────────────┘
```

## 2. IP Address Management (IPAM) Table

| Segment Name | Interface | Virtual Switch | Subnet | Gateway IP | Primary Host IP | Host Role |
|---|---|---|---|---|---|---|
| WAN | em0 | VirtualBox NAT | Dynamic | Upstream GW | Dynamic DHCP | Internet Uplink |
| Corporate (VLAN 10) | em1 | vlan10-corp | 10.10.10.0/24 | 10.10.10.1 | 10.10.10.50 | Windows 11 Pro Client |
| Server Tier (VLAN 20) | em2 | vlan20-servers | 10.10.20.0/24 | 10.10.20.1 | 10.10.20.10 | Windows Server 2022 (AD/DNS) |
| Security Lab (VLAN 30) | em3 | vlan30-security | 10.10.30.0/24 | 10.10.30.1 | 10.10.30.50 | Kali Linux Inspection Node |


---

## 3. Real-World NOC Incident Log & Triage Cases

### Incident 01: Host IP Assigned to Gateway Interface (Routing Blackhole)
* **Symptom:** Windows 11 client and Windows Server reported "No Internet" and timed out pinging their default gateways (`10.10.10.1` and `10.10.20.1`).
* **Root Cause Analysis (RCA):** During initial interface IP assignment on OPNsense, the DHCP client pool starting IP (`.50`) was entered into the firewall interface IP prompt instead of `.1`. OPNsense adopted `10.10.10.50` and `10.10.20.50`, breaking the default gateway hierarchy and causing IP conflicts with clients.
* **Resolution:** Used OPNsense console menu Option 2 to reassign gateways to `10.10.10.1/24` on LAN (`em1`) and `10.10.20.1/24` on OPT1 (`em2`), reserving `.100`–`.200` for dynamic DHCP leases.

### Incident 02: OPNsense Default-Deny on Optional Interfaces
* **Symptom:** Windows 11 could ping Kali Linux (`10.10.30.50`), but Kali could neither ping Windows 11 nor its own gateway (`10.10.30.1`).
* **Root Cause Analysis (RCA):** OPNsense creates a default-allow rule on the primary `LAN` interface, but applies a strict **Default Deny (Zero Trust)** policy on optional interfaces (`OPT1`, `OPT2`). Return packets from Windows 11 succeeded due to stateful connection tracking, but new connections originating from Kali were dropped immediately.
* **Resolution:** Navigated to **Firewall > Rules > OPT2** in the WebGUI and added an explicit stateful pass rule:
  * *Action:* `Pass` | *Interface:* `OPT2` | *Protocol:* `any` | *Source:* `OPT2 net` | *Destination:* `any`

### Incident 03: Windows Defender Dropping Cross-Subnet ICMP (Scope Restriction)
* **Symptom:** Kali Linux could reach its gateway and public internet, but pings to Windows 11 (`10.10.10.50`) failed with 100% packet loss despite OPNsense rules permitting the transit.
* **Root Cause Analysis (RCA):** The default Windows Defender Firewall "File and Printer Sharing (Echo Request - ICMPv4-In)" rule was scoped strictly to "Local Subnet Only". Packets arriving from `10.10.30.0/24` were categorized as remote and dropped at the host layer.
* **Resolution:** Executed host firewall rule update in Windows 11 to permit ICMP across routed subnets:
  ```cmd
  netsh advfirewall firewall add rule name="Allow ICMP from All Subnets" dir=in action=allow protocol=icmpv4:any,any remoteip=any

### Incident 04: Active Directory External DNS Blackholing
* **Symptom:** Windows 11 could ping public IP addresses ('8.8.8.8, 1.1.1.1 and 9.9.9.9'), but could not resolve external domain names ('google.com').
* **Root Cause Analysis (RCA):** Windows 11 had its primary DNS pointed exclusively to the Domain Controller ('10.10.20.10'). Windows Server 2022 resolved internal 'pmm.edu' records but had no DNS Forwarders configured to resolve external public queries.
* **Resolution:** Opened DNS Manager on Windows Server 2022 ('MY-DC-01') and added recursive DNS Forwarders pointing to Quad9 (9.9.9.9).


## 4. Packet Inspection & Diagnostic Verification

### 4.1 Layer 2 ARP Table Verification (Neighbor Discovery)

Confirmed Layer 2 resolution between Kali Linux and the OPNsense gateway interface:
```cmd
ip neigh show
```
Output Observed:
```cmd
10.10.30.1 dev eth0 lladdr 08:00:27:xx:xx:xx REACHABLE
```
*(The transition from INCOMPLETE to REACHABLE/STALE proves that Layer 2 virtual switching and MAC address resolution succeeded).*

### 4.2 Transport Layer Handshake Capture (`tcpdump`)

Captured the TCP 3-Way Handshake flags during session initialization to the OPNsense WebGUI:
```cmd
sudo tcpdump -nn -i eth0 "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0" -c 6
```

Captured Packet Flow:

1.`[S]` (SYN) — Client sequence number initialization

2.`[S.]` (SYN-ACK) — Gateway synchronization acknowledgement

3.`[.]` (ACK) — Session established state


### 4.3 Socket State & Listening Port Inspection (`ss`)
Verified local transport-layer socket bindings on Linux endpoints:

```cmd
ss -tuna
```
- Checked listening sockets (`LISTEN`) on critical services before network transit testing.
- Validated active sockets (`ESTAB`) during active HTTPS and DNS traffic sessions.















