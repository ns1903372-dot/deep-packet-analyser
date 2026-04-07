## Overview

This repository now includes a Java implementation of the deep packet analyser. The Java CLI ports the core end-to-end DPI flow from the original C++ version:

- read `.pcap` files
- parse Ethernet, IPv4, TCP, and UDP packets
- extract TLS SNI and HTTP `Host` values
- classify traffic by application or domain
- apply blocking rules
- write forwarded packets to a filtered output PCAP

The original C++ implementation is still available in the `Packet_anal-main` folder as a reference during migration.

## Java Project Layout

- `src/main/java/com/ns1903372dot/dpi/DeepPacketAnalyser.java`: CLI entry point
- `src/main/java/com/ns1903372dot/dpi/PcapIo.java`: PCAP read and write support
- `src/main/java/com/ns1903372dot/dpi/PacketParser.java`: Ethernet, IPv4, TCP, and UDP parser
- `src/main/java/com/ns1903372dot/dpi/DpiSupport.java`: SNI extraction, host extraction, classification, rules, and reporting
- `src/main/java/com/ns1903372dot/dpi/AppType.java`: application categories
- `src/main/java/com/ns1903372dot/dpi/FiveTuple.java`: flow key model

## Build And Run

Java and `javac` are enough to run the current port:

```powershell
New-Item -ItemType Directory -Force out
javac -d out src/main/java/com/ns1903372dot/dpi/*.java
java -cp out com.ns1903372dot.dpi.DeepPacketAnalyser Packet_anal-main/test_dpi.pcap filtered_output.pcap --block-app YouTube
```

A minimal `pom.xml` is included for environments that have Maven installed.

## Current Scope Of The Java Port

The Java version currently covers the simplified DPI pipeline:

- offline PCAP processing
- five-tuple flow tracking
- TLS SNI extraction
- HTTP host extraction
- application classification
- block-by-IP, app, or domain rules
- filtered PCAP output
- summary reporting

The advanced multi-threaded C++ engine has not been fully ported yet.
