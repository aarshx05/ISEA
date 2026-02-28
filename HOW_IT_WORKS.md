# ISEA — How It Works & Why It's Different

## What Is ISEA?

ISEA (Intelligent Storage Evidence Analyzer) is a forensic analysis platform that examines raw disk images and answers one question: **Was this storage device deliberately wiped, and if so — by whom, using what tool, and why?**

Standard forensic tools tell you *what's on a disk*. ISEA tells you *what was deliberately removed* — and builds a behavioral case around it.

---

## The Core Problem It Solves

When a suspect hands over a laptop or a company seizes a server, the most incriminating data is often already gone. Three scenarios look identical to a naive tool:

| Scenario | What Happened | What a Naive Tool Sees |
|---|---|---|
| Normal use | Files deleted, OS recycled clusters | "Empty space" |
| IT maintenance | Drive reimaged before decommission | "Empty space" |
| Evidence destruction | Deliberate wipe with DBAN/shred/sdelete | "Empty space" |

ISEA distinguishes all three through **entropy physics** — every wiping method leaves a different thermodynamic fingerprint in the data it overwrites.

---

## The Detection Engine (How It Reads a Disk)

### Layer 1 — Shannon Entropy Analysis

Every cluster of bytes on a disk has an information-theoretic entropy value between 0.0 and 8.0 bits/byte.

```
0.0 – 3.5   →  natural_residual   (real files, OS data, low-entropy structure)
3.5 – 5.5   →  os_clear           (normal deletion — OS zeroed the cluster)
5.5 – 7.2   →  intentional_wipe   (deliberate overwrite — dd, sdelete, Eraser)
7.2 – 8.0   →  secure_erase       (cryptographically random fill — DBAN, /dev/urandom)
```

A disk that was normally used and then deleted looks like a scatter of natural_residual and os_clear. A wiped disk looks like a wall of intentional_wipe or secure_erase. ISEA reads every cluster and maps this landscape.

### Layer 2 — Wipe Tool Fingerprinting

Different tools don't just wipe — they wipe *consistently*, leaving tool-specific patterns:

| Tool | Signature |
|---|---|
| DBAN (DoD mode) | Alternating random + zero + random passes, entropy 7.8–8.0 |
| `shred` (GNU) | 3-pass: random → random → zero, entropy oscillates then drops |
| `sdelete` (Sysinternals) | Zero-fill with NTFS-aware cluster targeting, entropy 0.0 in NTFS slack |
| `cipher /W` (Windows) | Three-phase: 0x00 → 0xFF → random, detectable by byte-value distribution |
| `dd if=/dev/urandom` | Pure random fill, entropy uniformly 7.9–8.0, no byte bias |
| `dd if=/dev/zero` | Uniform 0x00 fill, entropy exactly 0.0, fill_byte detected |
| Eraser (Windows) | Gutmann 35-pass pattern, creates highly regular entropy gradient |

ISEA matches each wipe region against all 8 profiles simultaneously and returns a confidence-ranked list.

### Layer 3 — Behavioral Intent Modeling

This is where ISEA goes beyond signature matching. Even if you can't prove *which* tool was used, the *pattern of behavior* reveals intent:

- **Locality scoring** — Was wiping targeted at specific directory regions, or spread uniformly? Targeted wiping of `/home/user/Documents` is more suspicious than wiping of unallocated space.
- **Temporal correlation** — Do filesystem timestamps show a burst of deletions immediately before the wipe? (Classic pre-wipe cleanup pattern)
- **Sensitive directory targeting** — Were the wiped regions in paths matching known evidence-bearing locations (`/var/log`, `AppData\Roaming`, browser cache, shell history)?
- **Intensity analysis** — What fraction of the disk was wiped? 5% suggests accidental; 80% suggests systematic evidence destruction.

These four signals are weighted and combined into a **0–100 evidence score**:

```
Evidence Score = 40% × Intent Score
              + 30% × Wipe Fraction
              + 20% × Signature Confidence
              + 10% × Region Count Factor
```

---

## The Agentic AI Layer

### What "Agentic" Means Here

Most forensic AI tools are wrappers — you paste a report in, they summarize it. ISEA's AI is different: it has **direct tool access** and reasons across evidence through multiple steps before answering.

When you ask the AI analyst a question, it doesn't just generate text. It runs a loop:

```
User question
     ↓
Model selects a tool to call
     ↓
Tool executes against the actual scan data
     ↓
Model receives results, decides: answer now or call another tool?
     ↓
Up to 6 iterations of tool use before final response
     ↓
Streamed answer to the browser
```

### The 8 Forensic Tools

The AI can call any of these at any point in its reasoning chain:

| Tool | What It Does |
|---|---|
| `get_scan_summary` | Pulls high-level stats: total clusters, wipe fraction, top tools detected |
| `analyze_disk_region` | Re-analyzes a specific cluster range on demand |
| `get_wipe_detections` | Lists all detected wipe regions with boundaries and confidence |
| `get_wipe_signature_match` | Gets the ranked tool match for a specific region |
| `get_intent_assessment` | Returns the full behavioral scoring breakdown |
| `get_directory_analysis` | Checks which filesystem paths overlap with wipe regions |
| `get_evidence_score_breakdown` | Explains each component of the 0–100 score |
| `generate_evidence_report` | Produces a structured JSON + Markdown forensic report |

### Intelligent Model Routing

The system auto-routes queries to the most capable model based on what's being asked:

- **Intent queries** ("Was this deliberate?", "What was the motive?") → `meta-llama/llama-4-maverick` — stronger reasoning model
- **Technical queries** ("What tool was used?", "Show me the entropy data") → `llama-3.3-70b-versatile` — fast, accurate

The routing is keyword-driven and transparent — no user configuration needed.

### Example Reasoning Chain

**User asks:** *"Is there any evidence the user was trying to hide specific files rather than doing a full wipe?"*

The model's internal chain:
1. Calls `get_wipe_detections` → finds 3 wipe regions
2. Calls `get_directory_analysis` → sees regions overlap with `/Documents` and `AppData/Roaming` but not system files
3. Calls `get_intent_assessment` → reads locality score of 78/100, sensitive_directory_hits: ["Documents", "AppData"]
4. Calls `get_evidence_score_breakdown` → notes 40-point intent contribution
5. Synthesizes: *"Yes — the wipe pattern is highly targeted. Regions map to user document storage and browser profile paths, while system32 and program files are untouched. This is inconsistent with IT maintenance (which would wipe uniformly) and consistent with targeted evidence destruction."*

No human had to tell it which tools to call or in which order.

---

## What Makes It Differentiated

### vs. Traditional Forensic Tools (Autopsy, FTK, EnCase)

| | Traditional Tools | ISEA |
|---|---|---|
| Wipe detection | Binary yes/no | Classified + tool-identified |
| Intent analysis | Manual examiner work | Automated behavioral scoring |
| AI interface | None | Conversational with tool access |
| Report generation | Fixed templates | AI-generated narrative + structured JSON |
| Accessibility | Requires forensic training | Usable by legal/compliance teams |

### vs. Generic AI (ChatGPT / Claude with a pasted report)

| | Generic AI + Report | ISEA Agent |
|---|---|---|
| Data access | Only what you paste | Live access to actual scan data |
| Tool use | None | 8 forensic tools |
| Re-analysis | Can't — no access | Can re-analyze any cluster range |
| Evidence generation | Fabricated (no grounding) | Grounded in real measurements |
| Chain of custody | None | Structured evidence report with confidence scores |

### The Forensic Defensibility Gap

Generic AI hallucinates confidence. ISEA's AI is **evidence-grounded**: every claim it makes can be traced to a specific tool call, which in turn traces to specific byte measurements on the disk. The generated reports include:

- Per-region entropy values (reproducible measurements)
- Tool match confidence scores with evidence items
- Behavioral scoring breakdown with labeled factors
- Incomplete wipe detection (intact clusters that survived — often recoverable evidence)

---

## The Real-Time Web Interface

The UI is designed for two audiences simultaneously:

**Forensic examiners** get the technical depth: per-cluster entropy classification, tool fingerprint confidence, pass count estimation, fill-byte detection.

**Legal and compliance teams** get the narrative layer: the evidence score gauge, the risk level badge, the AI analyst hypothesis in plain English, and a downloadable Markdown report suitable for legal proceedings.

The scan page streams events cluster-by-cluster as the engine works, giving live visibility into what's being found — not just a spinner and a result.
