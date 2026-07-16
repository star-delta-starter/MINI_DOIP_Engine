# Automotive DoIP & UDS Diagnostic Engine

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue)
![Protocol](https://img.shields.io/badge/Protocol-DoIP%20%7C%20UDS%20%7C%20ENET-success)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

## Overview
This repository contains a custom-built, Python-based Diagnostic over IP (DoIP) and Unified Diagnostic Services (UDS) engine designed for modern vehicle architectures (specifically targeted at BMW/MINI G-Series infrastructures). Developed as a weekend project where I served as the system architect, leveraging AI as a pair-programming assistant for the code-level implementation.

The project was born out of a reverse-engineering initiative to decode aftermarket diagnostic tablet communications. It goes beyond simple request/response scripts by implementing a robust, multi-layered packet decoding architecture and state-aware ECU session management.

## Physical Layer & Hardware Interception Setup
To achieve pure packet capture without protocol translation interference, a physical Man-in-the-Middle (MitM) hardware architecture was constructed:

1. **Custom Hardware Tap:** Engineered a physical OBD-II to RJ45 pigtail tap to break out the diagnostic tablet's internal ethernet lines (Tx/Rx).
2. **Network Routing:** Routed the physical connection through a Managed Network Switch configured with Port Mirroring (SPAN).
3. **Traffic Sniffing:** Captured raw DoIP payloads and UDS sequences using Wireshark, filtering out background broadcast noise to isolate the diagnostic tablet's authentication and data retrieval routines.

## Software Architecture & Key Features

This engine is structured into a 4-Layer OSI-style parsing architecture:

* **Layer 1: Dual-Stack ENET/DoIP Decoder:** Identifies and unpacks both standard ISO-13400 (DoIP) and proprietary BMW ENET protocol signatures dynamically.
* **Layer 2: UDS Protocol Decoder:** Maps raw hex to UDS Service IDs (SIDs) such as `0x22` (Read Data By Identifier), `0x27` (Security Access), and `0x31` (Routine Control).
* **Layer 3: Structural DID Engine:** Identifies standard Data Identifiers (e.g., `F190` for VIN, `F18B` for ECU Manufacturing Date) and parses them into human-readable formats.
* **Layer 4: Multi-Type Payload Decrypter:** Automatically slices inner payloads and attempts multi-type decryption (ASCII, int8, Big-Endian int16, Float32).

### Advanced Session Management & NRC Handling
Real-world ECUs do not always respond flawlessly. This engine features advanced fault tolerance:
* **Dynamic Authentication Sequencing:** Detects `29 08` / `29 09` Security Access demands and gracefully manages session teardowns and reconnects.
* **Smart NRC Evaluation:** Intercepts Negative Response Codes (NRC). If an ECU throws `NRC 21` (Busy) or `NRC 78` (Pending), the engine backs off and triggers the **Busy Repeat Request Tracker** for a secondary assault, ensuring zero data loss during high-load diagnostic sweeps.

## Usage

### Prerequisites
* Python 3.8+
* `PyYAML` module (`pip install pyyaml`)
* ENET Cable connected to the vehicle's OBD-II port.

### Configuration
Diagnostic requests are dynamically loaded from `UDS_payloads.yaml`. You must define your target modules and payload hex strings in this file. 

### Execution
Simply execute the main engine script:
```bash
python MINI_DOIP_engine.py

⚠️ Disclaimer

Educational and Research Purposes Only.
Interfacing with vehicle networks can cause irreversible damage to ECUs, deploy airbags, or disable critical safety systems. The author is not responsible for any damage, bricked modules, or safety incidents resulting from the use of this code. Always test on bench setups before connecting to a live vehicle network.
