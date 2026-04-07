## Overview

This repository is now a Java implementation of a deep packet analyser / DPI engine.

The project can:

- read `.pcap` files
- parse Ethernet, IPv4, TCP, and UDP packets
- extract TLS SNI and HTTP `Host` values
- classify traffic by application or domain
- apply block rules for IPs, apps, domains, and ports
- process traffic through load balancer and fast-path worker threads
- write forwarded packets to a filtered output PCAP
- generate thread and application reports

## Project Layout

- `src/main/java/com/ns1903372dot/dpi/DeepPacketAnalyser.java`: CLI entry point
- `src/main/java/com/ns1903372dot/dpi/DpiEngine.java`: engine orchestration
- `src/main/java/com/ns1903372dot/dpi/LoadBalancer.java`: load balancer workers
- `src/main/java/com/ns1903372dot/dpi/FastPathProcessor.java`: fast-path inspection workers
- `src/main/java/com/ns1903372dot/dpi/ConnectionTracker.java`: per-worker flow tracking
- `src/main/java/com/ns1903372dot/dpi/RuleManager.java`: block rule management
- `src/main/java/com/ns1903372dot/dpi/PcapIo.java`: PCAP read and write
- `src/main/java/com/ns1903372dot/dpi/PacketParser.java`: packet parsing
- `src/main/java/com/ns1903372dot/dpi/DpiSupport.java`: SNI extraction and domain classification
- `sample-data/test_dpi.pcap`: sample PCAP for testing

## Build And Run

```powershell
New-Item -ItemType Directory -Force out
javac -d out src/main/java/com/ns1903372dot/dpi/*.java
java -cp out com.ns1903372dot.dpi.DeepPacketAnalyser sample-data/test_dpi.pcap filtered_output.pcap --block-app YouTube --lbs 2 --fps-per-lb 2 --verbose
```

## Supported Options

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
- The repository has been cleaned to Java-only source code.
