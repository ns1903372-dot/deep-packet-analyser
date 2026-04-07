---
title: Deep Packet Analyser
emoji: 🐳
colorFrom: blue
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
---

## Overview

This repository is a Java deep packet analyser / DPI engine with a Hugging Face Spaces deployment setup.

The project can:

- read `.pcap` files
- parse Ethernet, IPv4, TCP, and UDP packets
- extract TLS SNI and HTTP `Host` values
- classify traffic by application or domain
- apply block rules for IPs, apps, domains, and ports
- process traffic through load balancer and fast-path worker threads
- write forwarded packets to a filtered output PCAP
- serve a browser UI for Hugging Face Spaces

## Project Layout

- `src/main/java/com/ns1903372dot/dpi/DeepPacketAnalyser.java`: CLI entry point
- `src/main/java/com/ns1903372dot/dpi/SpaceServer.java`: Hugging Face web server
- `src/main/java/com/ns1903372dot/dpi/DpiEngine.java`: engine orchestration
- `src/main/java/com/ns1903372dot/dpi/LoadBalancer.java`: load balancer workers
- `src/main/java/com/ns1903372dot/dpi/FastPathProcessor.java`: fast-path inspection workers
- `src/main/java/com/ns1903372dot/dpi/ConnectionTracker.java`: per-worker flow tracking
- `src/main/java/com/ns1903372dot/dpi/RuleManager.java`: block rule management
- `src/main/java/com/ns1903372dot/dpi/PcapIo.java`: PCAP read and write
- `src/main/java/com/ns1903372dot/dpi/PacketParser.java`: packet parsing
- `src/main/java/com/ns1903372dot/dpi/DpiSupport.java`: SNI extraction and domain classification
- `sample-data/test_dpi.pcap`: sample PCAP for testing
- `Dockerfile`: Hugging Face Docker Space image

## Local CLI Run

```powershell
New-Item -ItemType Directory -Force out
javac -d out src/main/java/com/ns1903372dot/dpi/*.java
java -cp out com.ns1903372dot.dpi.DeepPacketAnalyser sample-data/test_dpi.pcap filtered_output.pcap --block-app YouTube --lbs 2 --fps-per-lb 2 --verbose
```

## Local Space Run

```powershell
New-Item -ItemType Directory -Force out
javac -d out src/main/java/com/ns1903372dot/dpi/*.java
$env:PORT=7860
java -cp out com.ns1903372dot.dpi.SpaceServer
```

Then open `http://localhost:7860`.

## Hugging Face Deployment

Create a Docker Space and push this repository to it. The included `Dockerfile` will:

- compile the Java source
- start the web server on port `7860`
- expose an upload UI for `.pcap` analysis

The Space UI lets you:

- upload a PCAP file
- optionally block an app, IP, or domain
- run the Java DPI engine
- read the report
- download the filtered PCAP output

## Supported CLI Options

- `--block-ip <ip>`
- `--block-app <app>`
- `--block-domain <domain>`
- `--block-port <port>`
- `--rules-file <file>`
- `--lbs <count>`
- `--fps-per-lb <count>`
- `--queue-size <count>`
- `--verbose`

## Notes

- A minimal `pom.xml` is included for Maven-based environments.
- The repository is Java-only source code.
