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

This repository now has a clearer frontend and backend structure for the Java DPI project.

- Frontend: static web app for uploads, rule inputs, sample selection, report viewing, and downloads
- Backend: Java HTTP server and API endpoints that run the DPI engine and return results

## Architecture

Frontend files:

- `web/index.html`
- `web/styles.css`
- `web/app.js`

Backend files:

- `src/main/java/com/ns1903372dot/dpi/SpaceServer.java`
- `src/main/java/com/ns1903372dot/dpi/AnalysisService.java`
- `src/main/java/com/ns1903372dot/dpi/DpiEngine.java`
- `src/main/java/com/ns1903372dot/dpi/RuleManager.java`

Core engine files:

- `src/main/java/com/ns1903372dot/dpi/DeepPacketAnalyser.java`
- `src/main/java/com/ns1903372dot/dpi/FastPathProcessor.java`
- `src/main/java/com/ns1903372dot/dpi/LoadBalancer.java`
- `src/main/java/com/ns1903372dot/dpi/ConnectionTracker.java`
- `src/main/java/com/ns1903372dot/dpi/PacketParser.java`
- `src/main/java/com/ns1903372dot/dpi/PcapIo.java`

## API Endpoints

- `GET /api/health`
- `GET /api/examples`
- `POST /api/analyze`
- `GET /download?id=<token>`

## Run Locally

Compile:

```powershell
New-Item -ItemType Directory -Force out
javac -d out src/main/java/com/ns1903372dot/dpi/*.java
```

Run frontend + backend:

```powershell
$env:PORT=7860
java -cp out com.ns1903372dot.dpi.SpaceServer
```

Then open:

`http://localhost:7860`

## CLI Run

```powershell
java -cp out com.ns1903372dot.dpi.DeepPacketAnalyser sample-data/test_dpi.pcap filtered_output.pcap --block-app YouTube --lbs 2 --fps-per-lb 2 --verbose
```

## Features In The Web App

- upload a `.pcap` file
- use bundled example PCAPs
- block by app
- block by domain
- block by IP
- view report text
- view packet statistics
- download filtered output PCAP

## Deployment

The included `Dockerfile` is set up for Hugging Face Spaces Docker deployment.
