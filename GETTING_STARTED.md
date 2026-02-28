# ISEA — Getting Started Guide

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | Tested on 3.14 |
| Groq API Key | — | Free tier works. Get one at console.groq.com |
| Disk image | `.dd`, `.img`, `.raw`, `.bin` | Or generate a synthetic one (see below) |

---

## Step 1 — Install Dependencies

```bash
cd "path/to/ISEA"
pip install -r requirements.txt
```

This installs: `fastapi`, `uvicorn`, `groq`, `numpy`, `rich`, `click`, `jinja2`, `aiofiles`, `python-multipart`.

---

## Step 2 — Configure Your API Key

Copy the example env file:

```bash
cp .env.example .env
```

Open `.env` and set your key:

```
GROQ_API_KEY=gsk_your_key_here
```

> The key is only needed for the AI analyst chat feature. Scanning and reporting work without it.

---

## Step 3 — Start the Server

```bash
python server.py
```

Open **http://localhost:8000** in your browser.

> The server auto-reloads on code changes. To use a different port:
> ```bash
> PORT=9000 python server.py
> ```

---

## Step 4 — Get a Disk Image to Analyze

### Option A — Generate a Synthetic Test Image (fastest, no real disk needed)

```bash
python -c "
from tests.synthetic_generator import SyntheticDiskFactory
img = SyntheticDiskFactory.create_realistic_image(size_mb=10)
open('sample.img', 'wb').write(img)
print('Created sample.img')
"
```

This creates a 10 MB image with mixed natural data, deleted files, and a wiped region — enough to demonstrate all detection features.

**Other synthetic image types:**

```python
# Zero-filled (simulates sdelete / dd if=/dev/zero)
SyntheticDiskFactory.create_zero_filled_image(size_mb=10)

# Random-filled (simulates DBAN / dd if=/dev/urandom)
SyntheticDiskFactory.create_random_filled_image(size_mb=10)

# Mixed: some natural, some wiped (most realistic)
SyntheticDiskFactory.create_mixed_image(size_mb=10)

# Incomplete wipe (some clusters survived — good for recovery demo)
SyntheticDiskFactory.create_incomplete_wipe_image(size_mb=10)
```

### Option B — Acquire a Real Disk Image

**On Linux/macOS:**
```bash
# Full disk image (replace /dev/sdb with your target)
sudo dd if=/dev/sdb of=evidence.dd bs=4096 status=progress

# Specific partition
sudo dd if=/dev/sdb1 of=partition.dd bs=4096 status=progress
```

**On Windows (using FTK Imager or similar):**
- Use FTK Imager → File → Create Disk Image → select Raw (dd) format
- Save as `.dd` or `.img`

**Free forensic sample images for testing:**
- Digital Corpora: `digitalcorpora.org/corpora/disk-images`
- NIST CFReDS: `cfreds.nist.gov`

---

## Step 5 — Run Your First Analysis

1. Open **http://localhost:8000** in your browser
2. Drag your disk image onto the upload zone (or click to browse)
3. Select cluster size (default 4096 bytes is correct for most modern filesystems)
4. Select scan mode:
   - **Thorough** (step=1): Every cluster analyzed. Most accurate.
   - **Fast** (step=4): Every 4th cluster. ~4x faster, slightly less precise.
5. Click **Start Analysis**

You'll be taken to the live scan page showing:
- Real-time progress bar with cluster counter and ETA
- Live entropy readings per cluster
- Classification chart (natural / OS clear / wiped / secure erase)
- Wipe detections appearing as they're found

When the scan completes, the browser redirects automatically to the results page.

---

## Step 6 — Read the Results

The results page has five tabs:

### Overview
- **Evidence Score (0–100):** Composite forensic confidence score
- **Risk Level:** MINIMAL / LOW / MODERATE / HIGH / CRITICAL
- **AI Analyst Hypothesis:** Plain-English interpretation of findings
- Key metrics: total clusters, wipe fraction, scan duration

### Wipe Regions
Table of all detected wipe regions showing:
- Cluster range (start → end)
- Classification (intentional_wipe vs. secure_erase)
- Tool match and confidence
- Estimated pass count
- Mean entropy value

### Intent Analysis
Behavioral scoring breakdown:
- Locality score (was wiping targeted?)
- Sensitive directory hits
- Temporal correlation with deletions
- Intensity factor

### Tool Classification
Which wipe tool(s) were detected and evidence supporting each match.

### Full Report
Rendered Markdown report with download buttons for JSON and Markdown formats.

---

## Step 7 — Chat with the AI Analyst

From the results page, click **Ask AI Analyst**.

The AI has direct access to your scan data and can answer questions like:

- *"Was this wipe deliberate or could it be normal IT maintenance?"*
- *"Which specific files or directories were targeted?"*
- *"What's the strongest piece of evidence for intentional destruction?"*
- *"How confident are you in the tool identification?"*
- *"Generate a summary suitable for a legal brief."*

The AI uses tool calls to pull live data from your scan before answering — every claim is grounded in actual measurements.

---

## Command-Line Interface (Alternative to Web UI)

ISEA also has a full CLI for scripting and headless environments:

```bash
# Analyze a disk image and print results
python cli.py analyze sample.img

# Generate a JSON + Markdown report
python cli.py report sample.img --output ./reports/

# Run a quick scan (every 4th cluster)
python cli.py scan sample.img --step 4

# Interactive AI chat session
python cli.py chat sample.img
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

Expected output: **41 passed**. No real disk image is needed — the test suite uses the synthetic image factory.

---

## Troubleshooting

### "Scan not found" after uploading
The server was restarted between your upload and the scan page loading. State is in-memory — re-upload the file.

### AI chat returns "GROQ_API_KEY not set"
Add your key to the `.env` file and restart the server.

### Upload fails for large images (>500 MB)
The default upload limit in FastAPI is `python-multipart` default. For large images, use the CLI instead:
```bash
python cli.py analyze /path/to/large.dd
```

### Scan is slow on large images
Use step mode to sample every Nth cluster:
```bash
# Web UI: select "Fast Scan" in the upload form
# CLI: --step 8 for a quick triage scan
python cli.py analyze large.dd --step 8
```

### Port already in use
```bash
PORT=9000 python server.py
```

---

## File Structure Reference

```
ISEA/
├── server.py              # FastAPI web server (start here)
├── cli.py                 # Command-line interface
├── config.py              # API keys, model config, thresholds
├── requirements.txt
├── .env                   # Your API keys (create from .env.example)
│
├── core/
│   ├── disk_analyzer.py   # mmap-based disk image I/O
│   ├── entropy_engine.py  # Shannon entropy + classification
│   ├── intent_modeler.py  # Behavioral scoring
│   └── cluster_scanner.py # Pipeline orchestrator
│
├── signatures/
│   ├── wipe_signatures.py # Tool fingerprint matching
│   └── tool_profiles.json # 8 wipe tool profiles
│
├── agent/
│   ├── forensic_agent.py  # Groq agentic loop
│   ├── tools.py           # 8 forensic tools for the AI
│   └── report_generator.py# JSON + Markdown report output
│
├── templates/             # Jinja2 HTML templates
├── static/                # Shared JS utilities
├── uploads/               # Uploaded disk images (auto-created)
├── reports/               # Generated reports (auto-created)
└── tests/                 # 41 unit tests + synthetic image factory
```
