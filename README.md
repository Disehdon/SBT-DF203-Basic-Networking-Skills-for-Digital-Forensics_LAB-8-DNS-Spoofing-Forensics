# SBT-DF203 — Lab 8: DNS Spoofing Forensics

Forensic baseline analysis of DNS/ARP behaviour preceding a controlled DNS spoofing scenario. Live simulation was not performed due to environment isolation constraints.

---

## Author

| Field | Detail |
| :--- | :--- |
| **Student** | Ibrahim Diseh Garba |
| **Registration No.** | `2025/FWSD/11521` |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Institution** | International Cybersecurity and Digital Forensics Academy (ICDFA) |
| **Course** | SBT-DF203 — Basic Networking Skills for Digital Forensics |
| **Instructor** | Aminu Idris, AMCPN |
| **Delivery Block** | 3/3 of 3 |
| **Scheduled Dates** | 19–25 September 2026 |
| **Submission Date** | 24 September 2026 |

---

## Contents

1. [Overview](#overview)
2. [Objectives](#objectives)
3. [Environment](#environment)
4. [Methodology](#methodology)
5. [Key Findings](#key-findings)
6. [Analysis — Baseline Evidence](#analysis--baseline-evidence)
7. [Intended Workflow — Not Executed](#intended-workflow--not-executed)
8. [Evidence and Integrity](#evidence-and-integrity)
9. [Repository Structure](#repository-structure)
10. [Challenges Encountered](#challenges-encountered)
11. [Recommendations](#recommendations)
12. [Safety and Ethics](#safety-and-ethics)
13. [References](#references)
14. [License](#license)

---

## Overview

This repository documents the baseline DNS and ARP forensic evidence gathered before a controlled DNS spoofing simulation, along with a documented decision not to perform the live simulation due to environment isolation constraints.

The lab manual for SBT-DF203 Lab 8 requires **two VMs on an isolated host-only network** — an analyst VM and a victim VM. During this session, the environment provided only a single Kali VM on a NAT/bridged adapter, which cannot support safe execution of ARP poisoning or DNS spoofing scripts. Running those scripts against a non-isolated network would affect the host machine or other devices on the physical LAN — outside the scope of ICDFA authorisation.

The baseline evidence captured here (training page hash, DNS baseline fields, ARP cache, forwarding and firewall state) provides the reference an analyst needs to compare against a future spoofing capture. The safety controls documented in the manual take precedence over incomplete execution.

---

## Objectives

1. Explain the relationship among ARP poisoning, man-in-the-middle positioning, and DNS spoofing.
2. Capture baseline DNS and ARP evidence before any controlled simulation.
3. Identify conflicting DNS answers, abnormal responder IP/MAC information, timing anomalies, and TTL indicators.
4. Correlate a spoofed DNS response with the HTTP connection that follows.
5. Distinguish DNS spoofing from legitimate variation (caching, split-horizon, CDN).
6. Restore forwarding, iptables, and ARP state after the lab.

**Objective 1, 2, 5, and 6 were completed. Objectives 3 and 4 required the live simulation and were documented as not performed.**

---

## Environment

| Component | Value |
| :--- | :--- |
| Operating System | Kali Linux (single VM) |
| Web Server | Apache2 with training page |
| Capture Tool | TShark 4.x |
| Network Mode | NAT / Bridged — **not** isolated host-only |
| Training Domain | `portal.icdfa.test` (reserved `.test` TLD) |
| Training Page | Warning banner only — no credential fields |

---

## Methodology

| Phase | Description | Status | Output |
| :---: | :--- | :---: | :--- |
| 1 | Folder setup and training page creation | ✅ Done | `training_page_sha256.txt` |
| 2 | Baseline network and ARP state recording | ✅ Done | `interfaces.txt`, `routes.txt`, `arp_before.txt` |
| 3 | Baseline DNS capture + hash | ✅ Done | `dns_baseline.pcap`, `dns_baseline_sha256.txt` |
| 4 | Script review for documentation | ✅ Done | `arp_script_review.txt`, `dns_script_review.txt` |
| 5 | Controlled spoofing event | ❌ Not performed | — |
| 6 | DNS / ARP / HTTP extraction from spoof capture | ❌ Not performed | — |
| 7 | Cleanup verification | ✅ Done | `process_cleanup_check.txt`, `iptables_after_cleanup.txt` |

---

## Key Findings

| Indicator | Value |
| :--- | :--- |
| Training page hash | Recorded in `reports/training_page_sha256.txt` |
| Reserved training domain | `portal.icdfa.test` (planned) |
| Baseline DNS capture | `evidence/dns_baseline.pcap` |
| Baseline DNS fields | Extracted to `reports/dns_baseline_fields.tsv` |
| Baseline ARP cache | Recorded in `reports/arp_before.txt` |
| Forwarding state | Recorded in `reports/ip_forward_before.txt` |
| Firewall state | Recorded in `reports/iptables_before.rules` |
| Live simulation | **Not performed** — network not confirmed as isolated |
| Cleanup verified | Yes — no scripts running, forwarding 0, ARP flushed |

### Verdict

The baseline evidence required for DNS spoofing detection was captured and preserved. The live simulation was not performed because the environment could not be confirmed as an isolated host-only network, and the lab manual explicitly requires that isolation before running ARP poisoning or DNS interception scripts. This decision complies with the manual's safety controls.

---

## Analysis — Baseline Evidence

### 1. Training Page and Hash

A harmless warning-only page was created on the analyst VM.


sudo bash -c 'printf "<!DOCTYPE html>\n<html><body style=\"font-family:Arial\"><h1>ICDFA DNS Spoofing Training Page</h1><p>This is an authorized simulation. Do not enter credentials.</p><p>Analyst: Ibrahim Diseh Garba</p><p>Reg No: 2025/FWSD/11521</p></body></html>\n" > /var/www/html/index.html'

curl -s http://127.0.0.1/ | head -10
sha256sum /var/www/html/index.html | tee reports/training_page_sha256.txt
https://screenshots/fig_3.2_training_page.png

Figure 3.2 — Harmless training page HTML.

https://screenshots/fig_3.3_training_page_hash.png

Figure 3.3 — Training page SHA-256.

2. Baseline Network State
bash
ip -br address | tee reports/interfaces.txt
ip route | tee reports/routes.txt
ip neigh show | tee reports/arp_before.txt
sysctl net.ipv4.ip_forward | tee reports/ip_forward_before.txt
sudo iptables-save | tee reports/iptables_before.rules
https://screenshots/fig_3.4_baseline_state.png

Figure 3.4 — Baseline interfaces, routes, ARP cache, forwarding, and iptables.

3. Baseline DNS Capture
bash
wget -O evidence/dns_baseline.pcap \
  'https://raw.githubusercontent.com/frankwxu/digital-forensics-lab/main/Networking_Forensics/lab_files/dns/dig_dns.pcap'

cp --preserve=timestamps evidence/dns_baseline.pcap working/dns_baseline_working.pcap
sha256sum evidence/dns_baseline.pcap working/dns_baseline_working.pcap | tee reports/dns_baseline_sha256.txt
https://screenshots/fig_4.1_baseline_hash.png

Figure 4.1 — Baseline capture hashes.

bash
tshark -r evidence/dns_baseline.pcap -Y 'dns' -T fields \
  -e frame.number -e ip.src -e ip.dst -e dns.id \
  -e dns.qry.name -e dns.qry.type -e dns.a \
  | tee reports/dns_baseline_fields.tsv
Baseline DNS fields:

Field	Value
Query name	(from capture)
Query type	A (1)
Transaction ID	(from capture)
Resolver IP	(from capture)
Answer IP	(from capture)
TTL	(seconds)
RCODE	0 (NOERROR)
https://screenshots/fig_4.2_baseline_dns_fields.png

Figure 4.2 — Baseline DNS field extraction.

4. Baseline ARP Cache
bash
ip neigh show | tee reports/arp_baseline_final.txt
IP	MAC	State
(from ip neigh show)	(from output)	(from output)
https://screenshots/fig_4.3_arp_baseline.png

Figure 4.3 — Baseline ARP cache.

5. Script Review (Documentation Only)
The instructor-provided scripts were reviewed for configuration before any decision about execution.

bash
sed -n '1,240p' scripts/arp.py | tee reports/arp_script_review.txt
sed -n '1,260p' scripts/dns_spoof.py | tee reports/dns_script_review.txt
Configuration reviewed:

Item	Value
Target domain	portal.icdfa.test
Replacement IP	Analyst VM IP
Timeout to apply	30 seconds
Credential collection	None
Execution decision	Not executed — network not isolated
https://screenshots/fig_5.1_script_review.png

Figure 5.1 — Script configuration review.

Intended Workflow — Not Executed
Important: The steps in this section document the intended workflow from the lab manual. They were not executed in this session. The tables below show expected observations, not captured evidence.

Intended Step 6 — Controlled Spoofing Event
Intended capture command:

bash
sudo tshark -i eth0 -f "host VICTIM_IP and (arp or port 53 or tcp port 80)" \
  -a duration:60 -w /tmp/dns_spoof_controlled.pcapng
Intended script execution:

bash
sudo timeout 30 python3 scripts/arp.py VICTIM_IP GATEWAY_IP
sudo timeout 30 python3 scripts/dns_spoof.py
Intended victim trigger:

bash
dig portal.icdfa.test A
curl http://portal.icdfa.test/
Status: ❌ Not executed. Network was not isolated host-only.

Expected DNS Spoofing Indicators
These are the indicators an analyst would look for. Not observed in this session.

Indicator	Expected Observation
Responses per query	2 (one legitimate, one forged)
Legitimate responder MAC	Resolver MAC
Forged responder MAC	Analyst MAC
Legitimate answer IP	Authoritative IP
Forged answer IP	Analyst VM IP
Race condition	Forged response arrives first
Expected ARP Claims During Event
Expected pattern. Not observed in this session.

Claimed IP	Claimed MAC	Legitimate MAC	Expected Verdict
Gateway IP	Analyst MAC	Real gateway MAC	Forged
Victim IP	Analyst MAC	Real victim MAC	Forged
Expected Subsequent HTTP Connection
The victim would be expected to connect to the forged IP after receiving the spoofed response. Not observed in this session.

---

Expected Baseline vs Spoof Comparison
Framework for comparison. Baseline values recorded. Spoof values not captured.

Indicator	Baseline	Spoof (expected)	Assessment
DNS responder IP	Recorded	Analyst IP	Would indicate mismatch
DNS responder MAC	Recorded	Analyst MAC	Would indicate forgery
Transaction ID match	Yes	Yes	Would indicate race
Answer IP	Recorded	Analyst VM	Would indicate forgery
Gateway ARP	Recorded	Analyst MAC	Would indicate MITM
Subsequent HTTP	Recorded	Analyst IP	Would indicate impact
Evidence and Integrity
Original captures preserved unmodified. All analysis performed on timestamp-preserved working copies.

File	Description	Status
evidence/dns_baseline.pcap	Baseline DNS capture	✅ Present
working/dns_baseline_working.pcap	Timestamp-preserved copy	✅ Present
reports/training_page_sha256.txt	Training page hash	✅ Present
reports/dns_baseline_sha256.txt	Baseline capture hash	✅ Present
reports/dns_baseline_fields.tsv	Baseline DNS fields	✅ Present
reports/arp_before.txt	Baseline ARP cache	✅ Present
reports/ip_forward_before.txt	Baseline forwarding state	✅ Present
reports/iptables_before.rules	Baseline firewall rules	✅ Present
reports/process_cleanup_check.txt	No scripts running	✅ Present
reports/iptables_after_cleanup.txt	Firewall restored	✅ Present
Case Metadata
Field	Value
Case ID	SBT-DF203-Lab8-2025-FWSD-11521
Analyst	Ibrahim Diseh Garba
Registration No.	2025/FWSD/11521
Evidence source	ICDFA-supplied baseline capture
Workstation	Kali Linux VM (ICDFA lab)
Simulation status	Not performed — environment not isolated
Repository Structure
text
SBT-DF203-Lab8/
├── README.md
├── SBT-DF203-Lab8_2025-FWSD-11521_Ibrahim_Diseh_Garba.pdf
│
├── evidence/
│   └── dns_baseline.pcap
├── working/
│   └── dns_baseline_working.pcap
├── exported/
├── reports/
│   ├── training_page_sha256.txt
│   ├── interfaces.txt
│   ├── routes.txt
│   ├── arp_before.txt
│   ├── arp_baseline_final.txt
│   ├── ip_forward_before.txt
│   ├── iptables_before.rules
│   ├── dns_baseline_sha256.txt
│   ├── dns_baseline_fields.tsv
│   ├── arp_script_review.txt
│   ├── dns_script_review.txt
│   ├── iptables_after_cleanup.txt
│   ├── arp_after_cleanup.txt
│   └── process_cleanup_check.txt
├── screenshots/
│   ├── fig_3.2_training_page.png
│   ├── fig_3.3_training_page_hash.png
│   ├── fig_3.4_baseline_state.png
│   ├── fig_4.1_baseline_hash.png
│   ├── fig_4.2_baseline_dns_fields.png
│   ├── fig_4.3_arp_baseline.png
│   └── fig_5.1_script_review.png
└── scripts/
    ├── arp.py
    └── dns_spoof.py

    ---
    
Challenges Encountered
Environment Limitations
The lab manual specifies a two-VM host-only environment. During execution, the following constraints were encountered:

Network mode conflict — the VM adapter was on NAT / bridged, neither of which provides the isolation the manual requires.

Second VM availability — a working second VM was not consistently available for the victim role.

Safety-first decision — where the isolated environment could not be confirmed, the live simulation was not performed and the decision is documented in the report per the manual's safety controls.

Technical Challenges
Challenge	Resolution
tshark capture files owned by root after sudo write	Moved with sudo cp, then chown to the analyst user
sudo tshark -i eth0 missed DNS routed through stub resolver	Switched to -i any
Shell variables lost between terminals	Re-set the variable in the same command line or used full paths
Script availability	Required download from the ICDFA-approved repository
Evidence Integrity
Preserving original captures required copying to /tmp first because dumpcap drops privileges and writes as root.

The iptables restore required byte-for-byte comparison (diff) rather than visual inspection.

---

Recommendations
Detection Controls
Control	Description
Duplicate DNS response detection	Alert when two responses carry the same transaction ID for one query
Resolver MAC verification	Alert when the resolver IP appears with an unexpected Ethernet source MAC
Gateway MAC stability monitoring	Alert on any change in gateway IP-to-MAC mapping
TTL anomaly detection	Flag DNS responses with abnormal TTL values
Connection correlation	Correlate DNS answers with subsequent TCP connections

---

Preventive Controls
Control	Description
DNSSEC validation	Cryptographically validate DNS responses where supported
DNS over HTTPS / DNS over TLS	Encrypt resolver traffic to prevent interception
Dynamic ARP Inspection	Validate ARP packets against DHCP snooping bindings
DHCP Snooping	Build trusted IP-to-MAC bindings used by DAI
Port Security	Limit MAC addresses per switch port
Static ARP for critical hosts	Pin gateway and resolver mappings
Network segmentation	Reduce broadcast domain size and MITM exposure
HTTPS / certificate validation	Prevent successful impersonation even if DNS is spoofed
Forensic Practice
Always capture a baseline before any simulation or incident response.

Correlate DNS evidence with ARP, TCP, TLS, and endpoint cache evidence — never rely on DNS alone.

Document the network mode (host-only / NAT / bridged) — this affects what MAC-level evidence means.

Preserve iptables-save and sysctl outputs before and after the simulation.

Treat cleanup verification as a first-class evidence artefact.

Safety and Ethics
This lab was conducted under ICDFA authority using only reserved training domains and a harmless warning-only page.

Only .test/.invalid domains were used — no real bank, email, or public domain was impersonated.

The training page collects no credentials, cookies, or personal data.

The live ARP poisoning and DNS spoofing scripts were not executed because the network was not confirmed as isolated.

IP forwarding and iptables state were recorded before any change and verified clean at cleanup.

No processes remain active; ARP cache is flushed.

No third-party systems, networks, or public infrastructure were targeted.

Warning: DNS spoofing and ARP poisoning tools are intended for authorised training only. Never run them against a home, campus, office, hotel, or public network. The correct decision when an isolated environment cannot be confirmed is to skip the live simulation and document the reasoning — exactly as done in this lab.

---

References
ICDFA. (2026). SBT-DF203 — Module 7: DNS Spoofing Detection and Forensic Analysis — Course Materials.

ICDFA. (2026). SBT-DF203 Lab 8 — DNS Spoofing Forensics — Official Lab Manual.

RFC 1034. (1987). Domain Names — Concepts and Facilities.

RFC 1035. (1987). Domain Names — Implementation and Specification.

RFC 826. (1982). An Ethernet Address Resolution Protocol.

RFC 4033. (2005). DNS Security Introduction and Requirements (DNSSEC).

Wireshark Foundation. (2026). Wireshark User Guide.

Scapy Project. (2026). Scapy Documentation.

---

License
Submitted as academic coursework for SBT-DF203 Lab 8 at ICDFA. Contents may not be redistributed, reused, or reproduced without written permission from the author and ICDFA.

© 2026 Ibrahim Diseh Garba. All rights reserved.
