# detection-pipeline

**detection-pipeline** turns a list of threat indicators into detection rules across every rule engine in Nebula Forge — in a single command.

```
IOC input (CLI or file)
    ↓
Threat Intel Dashboard  POST /lookup
    ↓ (risk score + type)
Risk threshold filter
    ↓
┌───────────────┬───────────────┬───────────────────┐
SigmaForge      YaraForge       SnortForge
/api/generate   /api/generate   /api/build (Snort 2)
                                /api/build/snort3
└───────────────┴───────────────┴───────────────────┘
    ↓
output/{timestamp}/
    {type}/{ioc}/
        sigma.yml
        sigma_conversions.json
        rule.yar
        rule.snort2.rules
        rule.snort3.rules
    summary.json
    filtered_out.json
```

---

## Architecture

```
detection-pipeline/
├── main.py                         # CLI entry point
├── config.yaml                     # Runtime configuration
├── requirements.txt
├── README.md
└── pipeline/
    ├── models.py                   # IOC, EnrichedIOC, RuleResult, PipelineResult
    ├── ioc_parser.py               # CLI + file IOC collection and deduplication
    ├── enricher.py                 # Threat Intel Dashboard /lookup calls
    ├── dispatcher.py               # Fan-out to all builders with ThreadPoolExecutor
    ├── output_manager.py           # Writes rule files and summary.json
    └── builders/
        ├── sigma_builder.py        # SigmaForge /api/generate
        ├── yara_builder.py         # YaraForge /api/generate
        └── snort_builder.py        # SnortForge /api/build + /api/build/snort3
```

### Pipeline stages

| Stage | Module | What it does |
|---|---|---|
| **Parse** | `ioc_parser.py` | Collects IOCs from `--ioc` flags and/or `--file`, deduplicates |
| **Enrich** | `enricher.py` | Calls `POST /lookup` on each IOC; gets risk score, level, and auto-detected type |
| **Filter** | `dispatcher.py` | Skips IOCs below `risk_threshold`; unknown types are skipped with a note |
| **Dispatch** | `dispatcher.py` | Fires SigmaForge, YaraForge, and SnortForge concurrently per IOC |
| **Save** | `output_manager.py` | Writes all rule files; produces `summary.json` and `filtered_out.json` |

---

## IOC-type → rule-field mapping

| IOC type | SigmaForge | YaraForge | SnortForge |
|---|---|---|---|
| **IP** | `DestinationIp` (log: `network_connection`) | `text` string | `dst_ip` header field (`protocol ip`) |
| **Domain** | `QueryName` (log: `dns_query`) | `text` string | `content` match, `nocase`, `flow:established` |
| **Hash** | `Hashes` (log: `process_creation`) | `text` string | `content` match (hash literal in stream) |
| **URL** | `c-uri` (log: `proxy`) | `text` string | dual `contents`: netloc (`http_header`) + path (`http_uri`) |

MITRE ATT&CK tags applied per type: IP → T1071/T1071.001 · Domain → T1071.004 · Hash → T1204.002 · URL → T1071.001

---

## Setup

### Prerequisites

All four Nebula Forge services must be running:

| Service | Default port |
|---|---|
| SigmaForge | 5000 |
| Threat Intel Dashboard | 5001 |
| YaraForge | 5002 |
| SnortForge | 5003 |

Ports are configurable in `config.yaml`.

### Install

```bash
cd detection-pipeline
pip install -r requirements.txt
```

### Configure

Edit `config.yaml` — at minimum verify the service URLs and choose a `risk_threshold`:

```yaml
threat_intel_url: "http://127.0.0.1:5001"
sigmaforge_url:   "http://127.0.0.1:5000"
yaraforge_url:    "http://127.0.0.1:5002"
snortforge_url:   "http://127.0.0.1:5003"
risk_threshold: 30    # 0=all IOCs, 30=Medium+, 60=High/Critical only
```

---

## Usage

### Single IOC

```bash
python main.py --ioc 185.234.72.19
```

### Multiple IOCs inline

```bash
python main.py --ioc 185.234.72.19 --ioc evil-domain.xyz --ioc e3b0c44298fc1c149afbf4c8996fb924
```

### From file

```bash
python main.py --file iocs.txt
```

`iocs.txt` format — one IOC per line, `#` for comments:

```
# C2 IPs from incident IR-20260412
185.234.72.19
91.215.85.42

# Domains
update-service.xyz
invoice-portal.com

# SHA256 hashes
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Mixed sources

```bash
python main.py --ioc 185.234.72.19 --file more_iocs.txt
```

### Override threshold at runtime

```bash
python main.py --file iocs.txt --threshold 60
```

### Custom config or output directory

```bash
python main.py --file iocs.txt --config /path/to/config.yaml --output /mnt/rules/run1
```

### Verbose output

```bash
python main.py --ioc 185.234.72.19 --log-level DEBUG
```

---

## Output

Each run creates a timestamped directory under `output_dir`:

```
output/
  20260412_141500/
    summary.json           ← full manifest of the run
    filtered_out.json      ← IOCs below threshold (if any)
    ip/
      185_234_72_19/
        sigma.yml                   ← Sigma rule YAML
        sigma_conversions.json      ← All SIEM-backend conversions
        rule.yar                    ← YARA rule
        rule.snort2.rules           ← Snort 2 rule
        rule.snort3.rules           ← Snort 3 rule
    domain/
      evil_domain_xyz/
        ...
```

### summary.json structure

```json
{
  "run_directory": "...",
  "timestamp": "2026-04-12T14:15:00Z",
  "totals": { "input_iocs": 5, "processed": 3, "filtered_out": 2 },
  "rules_generated": { "sigma": 3, "yara": 3, "snort2": 3, "snort3": 3 },
  "rules_failed":    { "sigma": 0, "yara": 0, "snort2": 0, "snort3": 0 },
  "iocs": [
    {
      "value": "185.234.72.19",
      "ioc_type": "ip",
      "risk_score": 75,
      "risk_level": "HIGH",
      "demo_mode": true,
      "directory": "ip/185_234_72_19",
      "rules": {
        "sigma":  { "success": true, "file": "ip/185_234_72_19/sigma.yml" },
        "yara":   { "success": true, "file": "ip/185_234_72_19/rule.yar" },
        "snort2": { "success": true, "file": "ip/185_234_72_19/rule.snort2.rules" },
        "snort3": { "success": true, "file": "ip/185_234_72_19/rule.snort3.rules" }
      }
    }
  ]
}
```

---

## Partial failures

If one service is down the pipeline continues for the others. For example, if YaraForge is unreachable:

- Sigma and Snort rules are still generated and saved
- The YARA entry in `summary.json` shows `{"success": false, "error": "YaraForge unreachable at ..."}`
- `rules_failed.yara` is incremented in the summary

---

## SID / Rule ID allocation

Snort SIDs and Sigma Wazuh rule IDs are assigned as `base + rule_index` where `rule_index` increments per IOC processed (skipped IOCs do not consume an index). Set `sigma.rule_id_base` and `snort.sid_base` in `config.yaml` to ranges that do not conflict with your existing rule sets.

---

## Notes on hash IOC rules

For **YARA** and **Snort**, hash IOCs are matched as literal strings. This is useful for:
- Detecting hash values appearing in log files, PowerShell command lines, or HTTP download headers
- Finding threat reports or malware configs that reference the hash

It is **not** a byte-level binary signature. For binary matching, you need the actual file to extract byte patterns from.

For **SigmaForge**, the `Hashes` field in the `process_creation` log source is the standard Sysmon field that contains `SHA256=<hash>|MD5=<hash>` — the `contains` modifier handles this correctly.

---

## Tested against

- Threat Intel Dashboard v1.0
- SigmaForge v2
- YaraForge (Flask, `/api/generate` schema)
- SnortForge v1.0.0

---

## License

MIT
