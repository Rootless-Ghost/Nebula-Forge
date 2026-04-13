# Nebula Forge

> Open-source detection engineering and incident response tooling for SOC analysts and purple teams.

Built by a Navy veteran transitioning into cybersecurity — every tool in this org solves a real problem a SOC analyst faces daily. Not tutorial projects. Working tooling.

---

## What is Nebula Forge?

Nebula Forge is a detection engineering and IR platform covering the full SOC workflow. Each tool occupies a defined lane — from writing detection rules to collecting forensic evidence to generating incident reports. The flagship capability is the closed-loop validation pipeline between **SigmaForge** and **EndpointForge**: rules authored in SigmaForge deploy as native Wazuh XML and get validated against live endpoint telemetry from EndpointForge — closing the gap between writing a detection and knowing it actually works.

---

## The pipeline

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': {'clusterBkg': '#1a1a2e', 'clusterBorder': '#444', 'titleColor': '#ffffff'}}}%%
flowchart LR
    subgraph Detect
        SF[SigmaForge v2\nDetection rule authoring]
        YF[YaraForge\nFile-based signatures]
        SNF[SnortForge\nNetwork signatures]
        EF[EndpointForge\nRuntime telemetry]
    end

    subgraph Investigate
        ET[EndpointTriage\nForensic collection]
        DV[Detection validation\nSigma → Wazuh → live]
    end

    subgraph Respond
        IR[IR triage\nContain and mitigate]
    end

    subgraph Report
        SR[SIREN\nIR report generation]
    end

    subgraph Pipelines
        TI[Threat Intel Dashboard\nIOC enrichment]
        DP[detection-pipeline\nIOC → rules]
        IC[ir-chain\nAutomated IR]
    end

    ND[nebula-dashboard\nCentral hub]

    SF -->|Wazuh XML rules| DV
    EF -->|Live telemetry| DV
    EF -->|Run Full Triage| ET
    DV -->|Detection gap| SF
    ET --> IR
    IR --> SR

    TI -->|Enriched IOCs| DP
    DP -->|Sigma rules| SF
    DP -->|YARA rules| YF
    DP -->|Snort rules| SNF

    ET -->|Triage output| IC
    IC -->|Log analysis| IC
    IC -->|Incident payload| SR

    ND -.->|monitors| SF
    ND -.->|monitors| YF
    ND -.->|monitors| SNF
    ND -.->|monitors| EF
    ND -.->|monitors| TI
    ND -.->|monitors| SR
    ND -.->|monitors| DP
    ND -.->|monitors| IC

    classDef detect     fill:#1e3a5f,stroke:#2a5a9f,color:#fff
    classDef investigate fill:#3a1e5f,stroke:#5a2a9f,color:#fff
    classDef respond    fill:#5f1e1e,stroke:#9f2a2a,color:#fff
    classDef report     fill:#1e5f3a,stroke:#2a9f5a,color:#fff
    classDef pipeline   fill:#1e4a4a,stroke:#2a7a7a,color:#fff
    classDef hub        fill:#5f4a1e,stroke:#9f7a2a,color:#fff

    class SF,YF,SNF,EF detect
    class ET,DV investigate
    class IR respond
    class SR report
    class TI,DP,IC pipeline
    class ND hub

```

---

## Tools

| Tool | Purpose | Phase | Stack |
|------|---------|-------|-------|
| [SigmaForge v2](./SigmaForge) | Custom Sigma conversion engine — 6 query backends (Splunk SPL, Elastic KQL, EQL, Sentinel KQL, Wazuh XML, QRadar AQL) plus Detection-as-Code JSON; no pySigma dependency | Detect | Flask, Python, CLI |
| [YaraForge](./YaraForge) | YARA rule builder with SQLite storage, live file scanning via yara-python, MITRE ATT&CK tagging, and bulk import/export | Detect | Flask, Python, SQLite |
| [SnortForge](./SnortForge) | Snort 2 and Snort 3 rule generator with multi-content chaining, PCRE support, and a 0–100 performance scorer with letter grade and actionable tips | Detect | Flask, Python, CLI |
| [EndpointForge](./EndpointForge) | Cross-platform HIDS with five scan modules — processes, network connections, filesystem integrity, registry (Windows), and persistence — MITRE ATT&CK mapped, with Wazuh log export | Detect | Flask, Python, CLI |
| [EndpointTriage](./EndpointTriage) | PowerShell forensic collector — 13 artifact categories (processes with hashes, network, scheduled tasks, registry persistence, event logs, DNS cache, named pipes, ARP, and more), outputs CSV/TXT files and a consolidated HTML report | Investigate | PowerShell |
| [SIREN](./SIREN) | NIST 800-61 IR report builder with timeline events, IOC and affected-system tracking, composite severity scoring (0–10), and Markdown/JSON export | Report | Flask, Python |
| [ir-chain](./ir-chain) | Automated IR pipeline — connects EndpointTriage, log-analyzer, and SIREN into a single zero-touch workflow; watches for new triage output, runs log analysis, and POSTs a structured incident payload to SIREN; `--purge-processed` flag deletes processed case folders older than a configurable retention window (default 30 days) | Integrate | Python, CLI |
| [detection-pipeline](./detection-pipeline) | IOC-to-rule automation — enriches indicators via Threat Intel Dashboard, filters by risk score, and fans out to SigmaForge, YaraForge, and SnortForge simultaneously to generate Sigma, YARA, and Snort rules in a single command | Detect | Python, CLI |
| [nebula-dashboard](./nebula-dashboard) | Central hub — live online/offline status for every Nebula Forge tool, one-click launch buttons, pipeline activity panels for ir-chain and detection-pipeline, SIREN incident report viewer (click any report to see full timeline, IOCs, affected systems, and recommendations), and a live countdown timer showing seconds until the next auto-refresh | Operate | Flask, Python |
| [Log Analyzer](./log-analyzer) | CLI tool for parsing Windows Security Event Log (CSV) and Linux auth.log; detects brute force (4625), off-hours logins (4624), privilege escalation (4728/4732/4756), and account lockouts (4740) | Detect | Python |
| [Phishing Analyzer](./phishing-analyzer) | CLI tool for analyzing .eml files; checks SPF/DKIM/DMARC, From/Reply-To mismatch, suspicious URLs (shorteners, TLDs, IP-based), dangerous attachments, and urgency keywords; scores suspicion 0–100 | Detect | Python |
| [Threat Intel Dashboard](./threat-intel-dashboard) | IOC reputation lookup for IPs, domains, file hashes, and URLs; queries VirusTotal and AbuseIPDB with auto-type detection; demo mode when no API keys are configured | Detect | Flask, Python |
| [Security Awareness Training](./security-awareness-training-main) | Multi-user web app with training modules, quizzes (70% pass threshold), phishing simulation scenarios with red-flag walkthroughs, and an admin dashboard for tracking user progress | Training | Flask, Python |

---

## Architecture

Every tool in Nebula Forge shares the same foundation:

- **Flask web UI** with a consistent dark theme
- **Python CLI engine** for scripting and automation
- **MITRE ATT&CK mapping** across detections and findings
- **Wazuh integration** where applicable — decoders, rules, and exporters

The SigmaForge ↔ EndpointForge cross-link uses a custom Sigma conversion engine — no pySigma dependency, which has no native Wazuh backend. Rules generated by SigmaForge are valid Wazuh XML out of the box.

---

## Home lab

All tooling is validated against a live environment:

- **Wazuh server** — 192.168.46.100, v4.14.4
- **Agents** — Win11x01 (windows), SOC101-Ubuntu (linux), Kali-Purple (offensive), Nebula-C (offensive)
- **Sysmon** — SwiftOnSecurity config deployed on Win11x01

---

## Built by

[Rootless-Ghost](https://github.com/Rootless-Ghost) — Navy Corpsman, SOC analyst in training, purple team practitioner. Targeting SOC analyst and detection engineering roles in the Tampa Bay market.

PSAA → PSAP → Sec+ → CCDL1 → PAPA → PJPT + PNPT

---

*Nebula Forge — detection engineering tooling that works in the real world.*
