# Man-in-the-Middle Attack Framework  
## ARP Poisoning, DNS Spoofing, and SSL Stripping with Scapy


## Overview
This project implements a modular Man-in-the-Middle (MitM) framework built using Scapy. It integrates ARP poisoning, DNS spoofing, and SSL stripping into a single tool that supports controlled experiments on local networks.

The framework is exposed through a unified command-line interface and is intended for educational use in authorised environments only.


## Architecture

The system is organised into independent Python modules coordinated by a central entry point:

- `prog.py` – main command-line interface and orchestrator  
- `arp_poison.py` – ARP poisoning (continuous and reactive) and ARP watcher mode  
- `dns_poison.py` – selective DNS spoofing based on a domain-to-IP mapping file  
- `ssl_strip.py` – ARP spoofing + HTTP interception and payload rewriting with transparent forwarding  
- `dns-file.txt` – domain-to-IP mappings for DNS spoofing  
- `arp-watcher.db` (generated) – IP–MAC database produced by ARP watcher and reused for MAC resolution


## Implemented Functionality

- ARP poisoning modes:
  - continuous (gratuitous) poisoning
  - reactive (callback) poisoning based on observed ARP requests
  - passive ARP watcher that records IP–MAC pairs to `arp-watcher.db`
- DNS spoofing:
  - selectively forges DNS responses using `dns-file.txt`
  - limited to DNS A-record queries
  - can be restricted to a specific victim host
- SSL stripping:
  - intercepts TCP port 80 traffic and rewrites HTTP payloads (e.g., `https://` to `http://`)
  - modifies security-related headers (e.g., HSTS) and cookie attributes (e.g., `Secure`)
  - forwards packets at Ethernet level after modification and checksum recalculation
  - uses firewall rules to prevent kernel-level forwarding of intercepted HTTP traffic


## Instructions

This section describes how to install dependencies, configure the environment, and run the framework.

(To be completed.)


## Limitations

- SSL stripping is largely ineffective against modern HTTPS deployments (e.g., HSTS/HTTPS-first behaviour).
- DNS spoofing is limited to A-record queries.
- The framework assumes a local network without active MitM protections (e.g., dynamic ARP inspection).


## Ethical Notice

This framework is intended strictly for educational and research purposes. All experiments must be performed only on systems and networks for which explicit authorisation has been obtained.
