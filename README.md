# 🗺️ Atlas — AI-Powered Subdomain Enumerator

> Inspired by the **ai4eh workshop**

A powerful subdomain enumeration tool that combines passive recon, AI prediction, NLP keyword extraction, LLM-based wordlist generation, and a smart mutation engine — all while keeping the final wordlist lean and DNS-ready.

---

## ✨ Features

| Module | What it does |
|---|---|
| **subfinder** | Passive subdomain discovery via OSINT sources |
| **SubWiz** | AI-based subdomain prediction from known subs |
| **CeWL-style scraper** | Pure Python web scraper — no Ruby dependency |
| **NLTK NLP** | Lemmatized keyword extraction from scraped content |
| **Claude (LLM)** | Context-aware wordlist generation + keyword enrichment |
| **Mutation engine** | Smart suffix swaps, env affixes & part recombination |
| **puredns** | High-speed DNS brute-force resolution |
| **httpx** | Live host probing with status codes & tech detection |

---

## 🚀 Installation

### Python dependencies
```bash
pip install requests html2text nltk subwiz anthropic --break-system-packages
```

### Go tools
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### API key
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## 🛠️ Usage

```bash
python3 atlas.py -d example.com
```

### Common examples

```bash
# Basic run against a target
python3 atlas.py -d example.com

# Custom output directory
python3 atlas.py -d example.com -o ./results

# Increase the final wordlist cap (default: 5000)
python3 atlas.py -d example.com --wordlist-max 10000

# Tighten the mutation engine budget (default: 2000)
python3 atlas.py -d example.com --mutation-budget 500

# Only generate the wordlist — skip DNS resolution
python3 atlas.py -d example.com --wordlist-only

# Pass your API key inline instead of via env var
python3 atlas.py -d example.com -k sk-ant-...

# Skip specific steps
python3 atlas.py -d example.com --no-llm --no-subwiz
```

---

## ⚙️ All flags

| Flag | Default | Description |
|---|---|---|
| `-d`, `--domain` | *(required)* | Target domain |
| `-o`, `--output` | `atlas_<domain>` | Output directory |
| `-m`, `--model` | `claude-sonnet-4-6` | Claude model to use |
| `-k`, `--api-key` | env var | Anthropic API key |
| `--wordlist-max` | `5000` | Hard cap on final wordlist size |
| `--mutation-budget` | `2000` | Max entries the mutation engine may add |
| `--subwiz-timeout` | `300` | Timeout in seconds for SubWiz |
| `--wordlist-only` | `false` | Stop after wordlist, skip DNS |
| `--no-subfinder` | — | Skip subfinder |
| `--no-subwiz` | — | Skip SubWiz |
| `--no-scrape` | — | Skip web scraping |
| `--no-nltk` | — | Skip NLTK extraction |
| `--no-llm` | — | Skip all Claude steps |
| `--no-mutate` | — | Skip mutation engine |
| `--no-puredns` | — | Skip DNS brute-force |
| `--no-httpx` | — | Skip live host probing |

---

## 🧬 How the mutation engine works

Instead of generating millions of permutations like alterx can, the built-in mutation engine uses three targeted strategies with hard caps at every stage:

1. **Suffix swaps** — replaces known word endings with semantic equivalents.
   `ethical-hacking` → `ethical-hacker`, `ethical-hackers`, `ethical-hack`

2. **Env affixes** — prepends/appends common environment tags.
   `api` → `dev-api`, `staging-api`, `api-v2`, `api-internal`

3. **Part recombination** — splits hyphenated labels and cross-combines parts across all discovered subdomains.
   `ethical-hacking` + `red-team` → `ethical-team`, `red-hacking`

**Anti-explosion controls:**
- Max **8 mutations per label**
- Max **2000 total mutations** per run (override with `--mutation-budget`)
- Part recombination limited to **60 sampled parts** to avoid O(n²) blowup
- Final **5000-entry hard cap** on the wordlist (override with `--wordlist-max`)

---

## 📁 Output files

All files are written to the output directory (`atlas_<domain>/` by default):

| File | Contents |
|---|---|
| `passive_subfinder.txt` | Raw subfinder results |
| `subwiz_predictions.txt` | SubWiz AI predictions |
| `scraped_content.txt` | Raw text scraped from the target |
| `nltk_keywords.txt` | NLP-extracted keywords |
| `llm_wordlist.txt` | Claude-generated subdomain candidates |
| `llm_enriched_keywords.txt` | Claude keyword enrichment results |
| `mutation_candidates.txt` | Mutation engine output |
| `combined_wordlist.txt` | Final merged & capped wordlist |
| `resolved_subdomains.txt` | puredns-resolved live subdomains |
| `all_subdomains.txt` | Passive + resolved, deduplicated |
| `httpx_results.json` | httpx JSON output with status/tech info |

---

## 📋 Requirements summary

- Python 3.10+
- Go 1.19+ (for subfinder, puredns, httpx)
- An [Anthropic API key](https://console.anthropic.com/) for Claude steps

---

## ⚠️ Legal disclaimer

This tool is intended for **authorized security testing only**. Always ensure you have explicit written permission before running enumeration against any target. The authors take no responsibility for misuse.

---

## 🙏 Credits

- Inspired by the **ai4eh (AI for Ethical Hacking)** workshop
- Passive recon powered by [subfinder](https://github.com/projectdiscovery/subfinder)
- AI prediction by [SubWiz](https://github.com/ARPSyndicate/subwiz)
- DNS resolution by [puredns](https://github.com/d3mondev/puredns)
- Live probing by [httpx](https://github.com/projectdiscovery/httpx)
- LLM wordlist generation by [Claude](https://www.anthropic.com/claude) (Anthropic)
