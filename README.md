# ISEA — Intelligent Storage Evidence Analyzer

**AI-powered forensic disk wipe detection and attacker profiling system.**

---

## Features

- **Entropy-Based Detection**: Differentiates between natural file deletions and deliberate wiping using Shannon entropy physics.
- **Tool Fingerprinting**: Identifies the specific tool used (DBAN, shred, sdelete, etc.) based on data pattern signatures.
- **Interactive Scan Pipeline**: **[NEW]** The AI Analyst runs *during* the scan, streaming its real-time thought process into the UI.
- **Human-in-the-Loop (HITL)**: **[NEW]** The Agent can pause the scan to ask the investigator for context, incorporating answers into its final verdict.
- **Behavioral Intent Modeling**: Calculates a 0–100 Evidence Score based on wipe locality, temporal correlations, and sensitive directory targeting.

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API key

```bash
cp .env.example .env
# Edit .env and add your GROQ_API_KEY
```

### 3. Run a scan

```bash
python cli.py analyze path/to/disk.dd
```

### 4. Interactive AI session

```bash
python cli.py chat path/to/disk.dd
```
Then ask questions like:
- "Was this wipe intentional?"
- "Which tool was most likely used?"
- "Was this a full disk wipe or selective?"
- "Generate a complete forensic report."

---

## Commands

| Command | Description |
|---------|-------------|
| `python cli.py analyze <image>` | Full scan with live progress + findings table |
| `python cli.py report <image>` | Analyze + save JSON/Markdown reports to `./reports/` |
| `python cli.py scan <image> --step 4` | Quick sampling scan (every 4th cluster) |
| `python cli.py chat <image>` | Interactive AI analyst session |

---

## Architecture

```
raw disk image
      │
      ▼
DiskAnalyzer (mmap-based I/O)
      │
      ▼
EntropyEngine (Shannon entropy, byte patterns, classification)
      │                       │
      ▼                       ▼
IntentModeler          SignatureMatcher
(behavioral scoring)   (tool fingerprinting)
      │                       │
      └──────────┬────────────┘
                 ▼
          PipelineAgent ◄─────┐
     (Real-time Thoughts)     │
                 │            │ (Human Answer)
                 ▼            │
      [ Interactive UI ] ─────┘
                 │
                 ▼
           ScanResult (dataclass)
                 │
        ┌─────────┴─────────┐
        ▼                   ▼
   ForensicAgent       ReportGenerator
   (Post-scan Q&A)     (JSON + Markdown)
       │
       ▼
  CLI (Rich terminal UI)
```

---

## Detection Capabilities

| Wipe Type | Detected | Tool Identified |
|-----------|----------|-----------------|
| Zero fill (`dd if=/dev/zero`, `sdelete`) | ✓ | ✓ |
| Random fill (`dd if=/dev/urandom`) | ✓ | ✓ |
| DoD 5220.22-M (DBAN) | ✓ | ✓ |
| Gutmann 35-pass | ✓ | ✓ |
| GNU `shred` | ✓ | ✓ |
| Windows `cipher /W` | ✓ | ✓ |
| Incomplete/interrupted wipes | ✓ | — |

---

## Evidence Scoring

Each scan produces a 0–100 evidence score with a strength rating:

| Rating | Score | Meaning |
|--------|-------|---------|
| STRONG | 75–100 | High confidence of intentional destruction |
| PROBABLE | 50–74 | Evidence is likely but needs corroboration |
| POSSIBLE | 25–49 | Some indicators — investigate further |
| INSUFFICIENT | 0–24 | Consistent with routine OS behavior |

---

## Supported Models (Groq)

| Model | Usage |
|-------|-------|
| `llama-3.3-70b-versatile` | General forensic Q&A (default) |
| `meta-llama/llama-4-maverick` | Intent/attacker profiling queries |
| `qwen/qwen3-32b` | Supplementary classification |

---

## Supported Image Formats

- `.dd` / `.img` / `.raw` — plain binary (supported natively)
- `.E01` — EnCase format (requires `pip install pyewf`)

---

## Running Tests

```bash
pytest tests/ -v
```

41 tests, all passing. Tests use synthetic disk images — no real disk image required.

---

## Project Structure

```
ISEA/
├── core/
│   ├── disk_analyzer.py       # mmap-based disk image I/O
│   ├── entropy_engine.py      # Shannon entropy + pattern detection
│   ├── intent_modeler.py      # Behavioral intent scoring
│   └── cluster_scanner.py    # Pipeline orchestrator
├── signatures/
│   ├── wipe_signatures.py     # Tool signature matching engine
│   └── tool_profiles.json     # Known wipe tool database
├── agent/
│   ├── forensic_agent.py      # Groq agentic loop
│   ├── tools.py               # Agent tool definitions + executor
│   └── report_generator.py    # JSON + Markdown report builder
├── tests/
│   ├── synthetic_generator.py # Synthetic disk image factory
│   └── test_*.py              # Unit tests
├── cli.py                     # Rich CLI interface
├── config.py                  # Configuration
└── requirements.txt
```
