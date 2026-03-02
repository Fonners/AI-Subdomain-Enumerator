#!/usr/bin/env python3
"""
atlas.py — AI-Powered Subdomain Enumerator
Combines: subfinder, SubWiz, CeWL-style scraping, NLTK NLP, LLM-based
contextual wordlist generation, and a smart Python mutation engine to
maximize subdomain coverage without list explosion.

Requirements:
    pip install requests html2text nltk subwiz --break-system-packages
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/d3mondev/puredns/v2@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    pip install anthropic --break-system-packages
    export ANTHROPIC_API_KEY=sk-ant-...   # or pass via --api-key

Usage:
    python3 atlas.py -d example.com [options]
"""

import argparse
import os
import random
import re
import subprocess
import urllib.request
from collections import Counter
from pathlib import Path

# ─── Colour helpers ──────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""{CYAN}{BOLD}
   ██████╗  ████████╗ ██╗      ████████╗  ███████╗
  ██╔══██╗ ╚══██╔══╝ ██║      ██╔═══██║ ██╔═════╝
  ███████║    ██║    ██║      ████████╔╝ ╚██████╗ 
  ██╔══██║    ██║    ██║      ██╔═══██║   ╚════██╗
  ██║  ██║    ██║    ███████╗ ██║   ██║  ███████╔╝
  ╚═╝  ╚═╝    ╚═╝    ╚══════╝ ╚═╝   ╚═╝  ╚══════╝ 
{RESET}{YELLOW}  AI-Powered Subdomain Enumerator  |  inspired by ai4eh workshop  |  Made by Fonners  {RESET}
""")

def log(msg, level="info"):
    icons = {"info": f"{CYAN}[*]{RESET}", "ok": f"{GREEN}[+]{RESET}",
             "warn": f"{YELLOW}[!]{RESET}", "err": f"{RED}[-]{RESET}"}
    print(f"{icons.get(level, '[?]')} {msg}")

# ─── Tool availability checks ────────────────────────────────────────────────

def tool_exists(name: str) -> bool:
    if subprocess.run(["which", name], capture_output=True).returncode == 0:
        return True
    for extra in [Path.home() / "go/bin" / name, Path("/usr/local/bin") / name]:
        if extra.exists():
            os.environ["PATH"] = str(extra.parent) + os.pathsep + os.environ.get("PATH", "")
            return True
    return False

def check_tools(args):
    required = []
    if args.use_subfinder:
        required.append("subfinder")
    if args.use_subwiz:
        required.append("subwiz")
    if args.use_puredns:
        required.append("puredns")
    if args.use_httpx:
        required.append("httpx")
    missing = [t for t in required if not tool_exists(t)]
    if missing:
        log(f"Missing tools (will skip): {', '.join(missing)}", "warn")
    return set(required) - set(missing)

# ─── Step 1: subfinder passive enumeration ───────────────────────────────────

def run_subfinder(domain: str, out_file: str) -> list[str]:
    log(f"Running subfinder on {domain} …")
    subprocess.run(
        ["subfinder", "-d", domain, "-o", out_file, "-silent"],
        capture_output=True, text=True
    )
    if Path(out_file).exists():
        subs = [s.strip() for s in Path(out_file).read_text().splitlines() if s.strip()]
        log(f"subfinder found {len(subs)} subdomains", "ok")
        return subs
    log("subfinder produced no output", "warn")
    return []

# ─── Step 2: SubWiz AI subdomain prediction ──────────────────────────────────

def run_subwiz(known_subs_file: str, out_file: str, timeout: int = 300) -> list[str]:
    log(f"Running SubWiz AI subdomain prediction (timeout={timeout}s) …")
    try:
        subprocess.run(
            ["subwiz", "-i", known_subs_file, "-o", out_file],
            capture_output=True, text=True, timeout=timeout
        )
        if Path(out_file).exists():
            subs = [s.strip() for s in Path(out_file).read_text().splitlines() if s.strip()]
            log(f"SubWiz predicted {len(subs)} new subdomains", "ok")
            return subs
    except FileNotFoundError:
        log("SubWiz not installed — pip install subwiz", "warn")
    except subprocess.TimeoutExpired:
        log("SubWiz timed out", "warn")
    return []

# ─── Step 3: CeWL-style web scraper ──────────────────────────────────────────

def fetch_page_text(url: str, timeout: int = 15) -> str:
    try:
        import html2text
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (compatible; subenum/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        h = html2text.HTML2Text()
        h.ignore_links = True
        h.ignore_images = True
        return h.handle(html)
    except Exception as e:
        log(f"Could not fetch {url}: {e}", "warn")
        return ""

def scrape_target(domain: str, fallback_subs: list[str] | None = None, depth: int = 1) -> str:
    log(f"Scraping {domain} for CeWL-style keyword extraction …")
    pages_to_scrape = [f"https://{domain}", f"http://{domain}"]
    collected_text = []
    seen = set()

    for url in pages_to_scrape[:depth + 1]:
        if url in seen:
            continue
        seen.add(url)
        text = fetch_page_text(url)
        if text:
            collected_text.append(text)
            log(f"  Scraped {url} ({len(text)} chars)", "ok")

    if not collected_text and fallback_subs:
        log("Root domain unreachable — falling back to scraping known subdomains …", "warn")
        for sub in fallback_subs[:5]:
            for scheme in ("https", "http"):
                url = f"{scheme}://{sub}"
                if url in seen:
                    continue
                seen.add(url)
                text = fetch_page_text(url)
                if text:
                    collected_text.append(text)
                    log(f"  Scraped {url} ({len(text)} chars)", "ok")
                    break

    return "\n".join(collected_text)

# ─── Step 4: NLTK NLP keyword extraction ─────────────────────────────────────

def nltk_keywords(text: str, min_len: int = 3, max_len: int = 30) -> list[str]:
    try:
        import nltk
        from nltk.corpus import stopwords
        from nltk.tokenize import word_tokenize
        from nltk.stem import WordNetLemmatizer

        for pkg in ["punkt_tab", "stopwords", "wordnet", "punkt"]:
            try:
                nltk.download(pkg, quiet=True)
            except Exception:
                pass

        text = text.lower()
        text = re.sub(r"[^\w\s]", " ", text)
        tokens = word_tokenize(text)
        stop = set(stopwords.words("english"))
        lemmatizer = WordNetLemmatizer()

        keywords = []
        for token in tokens:
            if (min_len <= len(token) <= max_len
                    and token not in stop
                    and not token.isdigit()
                    and re.match(r"^[a-z][a-z0-9]*$", token)):
                keywords.append(lemmatizer.lemmatize(token))

        freq = Counter(keywords)
        unique = sorted(freq.keys(), key=lambda x: (-freq[x], x))
        log(f"NLTK extracted {len(unique)} unique keywords", "ok")
        return unique

    except ImportError:
        log("NLTK not installed — pip install nltk", "warn")
        words = re.findall(r"\b[a-z][a-z0-9]{2,29}\b", text.lower())
        return list(set(words))

# ─── Step 5: LLM contextual wordlist ─────────────────────────────────────────

def _claude_call(prompt: str, api_key: str, model: str) -> str:
    try:
        import anthropic
    except ImportError:
        log("anthropic library not installed — pip install anthropic --break-system-packages", "warn")
        return ""
    try:
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    except Exception as e:
        log(f"Claude API call failed: {e}", "warn")
        return ""


def llm_generate_wordlist(domain: str, context_text: str,
                           known_subs: list[str],
                           api_key: str = "",
                           model: str = "claude-sonnet-4-6",
                           count: int = 500) -> list[str]:
    """Use Claude to generate a context-aware subdomain wordlist.
    Passes already-discovered subdomains so Claude can generate morphological
    variants (e.g. ethical-hacking → ethical-hacker, ethical-hackers).
    """
    log(f"Asking Claude ({model}) to generate contextual wordlist …")
    trimmed = context_text[:4000] if len(context_text) > 4000 else context_text
    known_sample = "\n".join(known_subs[:50]) if known_subs else "(none yet)"

    prompt = (
        f"You are an expert subdomain enumerator assisting a security researcher "
        f"with authorized testing on {domain}.\n\n"
        f"ALREADY DISCOVERED SUBDOMAINS — use these to infer naming patterns and "
        f"generate morphological variants. For example: if you see 'ethical-hacking', "
        f"also generate 'ethical-hacker', 'ethical-hackers', 'hacker', 'hackers', etc.:\n"
        f"{known_sample}\n\n"
        f"Based on the website content below, generate a wordlist of {count} unique "
        f"subdomain label candidates tailored to THIS target. Include:\n"
        f"- Morphological variants of already-discovered subdomains (highest priority)\n"
        f"- Department and team names\n"
        f"- Environment names (dev, staging, prod, test, qa, uat)\n"
        f"- Technology-specific subdomains\n"
        f"- Non-English words if the site uses another language\n"
        f"- Geographic and regional subdomains\n"
        f"- API, internal tools, monitoring names\n\n"
        f"Rules: no spaces, may contain dashes, lowercase only, no full domains.\n"
        f"Return ONLY the wordlist, one entry per line, nothing else.\n\n"
        f"WEBSITE CONTENT:\n{trimmed}"
    )

    response = _claude_call(prompt, api_key, model)
    if response:
        words = [
            w.strip().lower()
            for w in response.splitlines()
            if w.strip() and re.match(r"^[a-z0-9][a-z0-9\-]{1,62}$", w.strip())
        ]
        log(f"Claude generated {len(words)} wordlist entries", "ok")
        return words
    return []


def llm_enrich_keywords(keywords: list[str], domain: str,
                         api_key: str = "",
                         model: str = "claude-sonnet-4-6") -> list[str]:
    if not keywords:
        return []
    log("Enriching NLP keywords with Claude …")
    keyword_sample = "\n".join(keywords[:200])

    prompt = (
        f"Based on the following keywords extracted from the {domain} website, "
        f"generate a unique and clever subdomain wordlist related to those keywords. "
        f"Consider synonyms, abbreviations, compound words, and industry terms. "
        f"Include non-English variations if the keywords suggest another language. "
        f"It must not contain spaces but may contain dashes. "
        f"Return ONLY the wordlist without any domain and nothing else.\n\n"
        f"KEYWORDS:\n{keyword_sample}"
    )
    response = _claude_call(prompt, api_key, model)
    if response:
        words = [
            w.strip().lower()
            for w in response.splitlines()
            if w.strip() and re.match(r"^[a-z0-9][a-z0-9\-]{1,62}$", w.strip())
        ]
        log(f"Claude keyword enrichment produced {len(words)} entries", "ok")
        return words
    return []

# ─── Step 6: Smart Python mutation engine ────────────────────────────────────
#
# Anti-explosion design:
#   • _PER_LABEL_CAP   : max mutations emitted per source label
#   • _MUTATION_BUDGET : hard total cap for the entire mutation step
#   • Part recombination runs last and is capped at 60 unique parts
#     to avoid the O(n²) explosion that killed alterx-style tools
#
# Three strategies, in priority order:
#   1. Suffix swaps   — hacking→hacker, admin→administrator, …
#   2. Env affixes    — dev-X, X-v2, …
#   3. Part recombination — cross-combine hyphen parts across all labels

SUFFIX_SWAPS: dict[str, list[str]] = {
    "hacking":       ["hacker", "hackers", "hack", "hacks"],
    "hacker":        ["hacking", "hackers", "hack"],
    "hackers":       ["hacking", "hacker", "hack"],
    "admin":         ["administrator", "admins", "administration", "mgmt"],
    "administrator": ["admin", "admins"],
    "login":         ["signin", "auth", "sso", "logon"],
    "signin":        ["login", "auth", "sso"],
    "auth":          ["login", "signin", "oauth", "sso", "idp"],
    "api":           ["apis", "api-v1", "api-v2", "graphql", "rest"],
    "app":           ["apps", "application", "web", "portal"],
    "portal":        ["app", "dashboard", "panel"],
    "dashboard":     ["portal", "panel", "console"],
    "mail":          ["email", "smtp", "webmail", "mx", "imap"],
    "webmail":       ["mail", "email", "smtp"],
    "shop":          ["store", "ecommerce", "cart", "checkout"],
    "store":         ["shop", "ecommerce", "cart"],
    "blog":          ["news", "press", "articles", "posts", "media"],
    "news":          ["blog", "press", "media"],
    "support":       ["help", "helpdesk", "desk", "tickets", "servicedesk"],
    "help":          ["support", "helpdesk", "faq", "docs"],
    "docs":          ["documentation", "wiki", "help", "kb", "knowledge"],
    "wiki":          ["docs", "kb", "confluence"],
    "dev":           ["develop", "developer", "development", "sandbox"],
    "prod":          ["production", "live"],
    "staging":       ["stage", "stg", "uat", "preprod"],
    "test":          ["testing", "qa", "sandbox", "uat"],
    "monitor":       ["monitoring", "metrics", "grafana", "prometheus"],
    "monitoring":    ["monitor", "metrics", "observability"],
    "vpn":           ["remote", "gateway", "tunnel"],
    "cdn":           ["assets", "static", "media", "files"],
    "static":        ["cdn", "assets", "files", "media"],
    "assets":        ["static", "cdn", "media"],
    "internal":      ["intranet", "corp", "private"],
    "intranet":      ["internal", "corp", "private"],
}

ENV_PREPENDS = ["dev", "staging", "test", "qa", "uat", "prod"]
ENV_APPENDS  = ["v2", "v3", "new", "old", "2", "internal"]

# Per-label and total mutation caps — tweak via --mutation-budget if needed
_PER_LABEL_CAP   = 8
_MUTATION_BUDGET = 2000


def _is_valid_label(s: str) -> bool:
    return bool(re.match(r"^[a-z0-9][a-z0-9\-]{0,62}$", s))


def mutate_wordlist(labels: list[str], budget: int = _MUTATION_BUDGET) -> list[str]:
    """
    Generate smart label mutations without list explosion.

    Per-label cap (_PER_LABEL_CAP) prevents any single label from
    dominating. Global budget stops the total count ballooning.
    Part recombination is limited to 60 sampled parts to keep it O(n)
    rather than O(n²).
    """
    if not labels:
        return []

    log(f"Running mutation engine on {len(labels)} labels "
        f"(per-label cap={_PER_LABEL_CAP}, budget={budget}) …")

    existing = set(labels)
    mutations: set[str] = set()

    # ── Strategies 1–3: per-label ─────────────────────────────────────────
    for label in labels:
        if len(mutations) >= budget:
            break

        per_label: list[str] = []

        # 1. Suffix swaps
        for key, swaps in SUFFIX_SWAPS.items():
            if label == key or label.endswith("-" + key):
                prefix = label[: -len(key)].rstrip("-")
                for swap in swaps:
                    candidate = f"{prefix}-{swap}".lstrip("-") if prefix else swap
                    if _is_valid_label(candidate) and candidate not in existing:
                        per_label.append(candidate)

        # 2. Env prepends (skip if the label itself is an env word)
        if label not in ENV_PREPENDS:
            for env in ENV_PREPENDS:
                candidate = f"{env}-{label}"
                if _is_valid_label(candidate) and candidate not in existing:
                    per_label.append(candidate)

        # 3. Env appends
        for sfx in ENV_APPENDS:
            candidate = f"{label}-{sfx}"
            if _is_valid_label(candidate) and candidate not in existing:
                per_label.append(candidate)

        for c in per_label[:_PER_LABEL_CAP]:
            mutations.add(c)
            if len(mutations) >= budget:
                break

    # ── Strategy 4: part recombination (lowest priority) ─────────────────
    remaining = budget - len(mutations)
    if remaining > 0:
        all_parts = sorted({
            part
            for label in labels
            for part in label.split("-")
            if len(part) >= 3
        })
        # Cap at 60 parts so pairwise combos stay manageable (~3600 pairs max)
        sampled = all_parts[:60]
        combos: list[str] = []
        for i, a in enumerate(sampled):
            for b in sampled[i + 1:]:
                for candidate in (f"{a}-{b}", f"{b}-{a}"):
                    if _is_valid_label(candidate) and candidate not in existing:
                        combos.append(candidate)

        random.seed(42)          # reproducible shuffle
        random.shuffle(combos)
        for c in combos[:remaining]:
            mutations.add(c)

    result = sorted(mutations - existing)
    log(f"Mutation engine produced {len(result)} new candidates", "ok")
    return result

# ─── Step 7: Combine, deduplicate & hard cap ─────────────────────────────────

WORDLIST_MAX = 5000

def cap_wordlist(words: list[str], limit: int = WORDLIST_MAX) -> list[str]:
    """Trim to *limit* entries, favouring shorter labels."""
    if len(words) <= limit:
        return words
    trimmed = sorted(words, key=lambda w: (len(w), w))[:limit]
    log(f"Wordlist capped at {limit} entries (was {len(words)})", "warn")
    return sorted(trimmed)


def build_combined_wordlist(domain: str,
                             passive_subs: list[str],
                             subwiz_subs: list[str],
                             nltk_words: list[str],
                             llm_words: list[str],
                             enriched_words: list[str]) -> list[str]:
    prefixes: set[str] = set()
    suffix = f".{domain}"
    for sub in passive_subs + subwiz_subs:
        prefix = sub[: -len(suffix)] if sub.endswith(suffix) else sub
        for part in prefix.split("."):
            if part:
                prefixes.add(part)

    combined = prefixes | set(nltk_words) | set(llm_words) | set(enriched_words)
    valid = sorted(
        w for w in combined
        if re.match(r"^[a-z0-9][a-z0-9\-]{0,62}$", w)
    )
    log(f"Pre-mutation wordlist: {len(valid)} unique entries", "ok")
    return valid

# ─── Step 8: puredns DNS brute-force ─────────────────────────────────────────

RESOLVERS_URL = (
    "https://raw.githubusercontent.com/trickest/resolvers/"
    "refs/heads/main/resolvers-trusted.txt"
)

def download_resolvers(path: str):
    if Path(path).exists():
        return
    log("Downloading trusted DNS resolvers …")
    try:
        urllib.request.urlretrieve(RESOLVERS_URL, path)
        log(f"Resolvers saved to {path}", "ok")
    except Exception as e:
        log(f"Could not download resolvers: {e}", "warn")

def run_puredns(domain: str, wordlist_file: str,
                resolvers_file: str, out_file: str) -> list[str]:
    log(f"Running puredns brute-force on {domain} …")
    subprocess.run(
        ["puredns", "bruteforce", wordlist_file, domain,
         "--resolvers", resolvers_file, "--write", out_file],
        capture_output=True, text=True
    )
    if Path(out_file).exists():
        found = [s.strip() for s in Path(out_file).read_text().splitlines() if s.strip()]
        log(f"puredns resolved {len(found)} live subdomains", "ok")
        return found
    log("puredns produced no output", "warn")
    return []

# ─── Step 9: httpx live check ────────────────────────────────────────────────

def run_httpx(hosts_file: str, out_file: str):
    log("Probing live hosts with httpx …")
    subprocess.run(
        ["httpx", "-l", hosts_file, "-json", "-follow-redirects",
         "-title", "-status-code", "-tech-detect", "-o", out_file, "-silent"],
        capture_output=True, text=True
    )
    if Path(out_file).exists():
        lines = Path(out_file).read_text().splitlines()
        log(f"httpx probed {len(lines)} live hosts", "ok")

# ─── Output helpers ──────────────────────────────────────────────────────────

def print_summary(domain, passive, subwiz, mutations, resolved, out_dir):
    print(f"\n{BOLD}{'─'*55}{RESET}")
    print(f"{BOLD}  SUMMARY for {domain}{RESET}")
    print(f"{'─'*55}")
    print(f"  Passive (subfinder)  : {len(passive):>6}")
    print(f"  SubWiz predictions   : {len(subwiz):>6}")
    print(f"  Mutation candidates  : {len(mutations):>6}")
    print(f"  Resolved (puredns)   : {len(resolved):>6}")
    print(f"  Output directory     : {out_dir}")
    print(f"{'─'*55}\n")

# ─── Argument parsing ─────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Atlas — AI-Powered Subdomain Enumerator"
    )
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("-o", "--output", default=None)
    p.add_argument("-m", "--model", default="claude-sonnet-4-6")
    p.add_argument("-k", "--api-key", dest="api_key", default="")
    p.add_argument("--wordlist-max", dest="wordlist_max", type=int, default=WORDLIST_MAX,
                   help=f"Hard cap on final wordlist (default: {WORDLIST_MAX})")
    p.add_argument("--mutation-budget", dest="mutation_budget", type=int,
                   default=_MUTATION_BUDGET,
                   help=f"Max entries the mutation engine may add (default: {_MUTATION_BUDGET})")

    p.add_argument("--no-subfinder", dest="use_subfinder", action="store_false", default=True)
    p.add_argument("--no-subwiz",    dest="use_subwiz",    action="store_false", default=True)
    p.add_argument("--no-scrape",    dest="use_scrape",    action="store_false", default=True)
    p.add_argument("--no-nltk",      dest="use_nltk",      action="store_false", default=True)
    p.add_argument("--no-llm",       dest="use_llm",       action="store_false", default=True)
    p.add_argument("--no-mutate",    dest="use_mutate",    action="store_false", default=True,
                   help="Skip the Python mutation engine")
    p.add_argument("--no-puredns",   dest="use_puredns",   action="store_false", default=True)
    p.add_argument("--no-httpx",     dest="use_httpx",     action="store_false", default=True)
    p.add_argument("--subwiz-timeout", dest="subwiz_timeout", type=int, default=300)
    p.add_argument("--wordlist-only", action="store_true")
    return p.parse_args()

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    banner()
    args = parse_args()
    domain = args.domain.lower().strip()

    out_dir = Path(args.output or f"atlas_{domain}")
    out_dir.mkdir(parents=True, exist_ok=True)
    log(f"Output directory: {out_dir}", "ok")

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if args.use_llm and not api_key:
        log("No Anthropic API key — skipping Claude steps. Use -k or set ANTHROPIC_API_KEY.", "warn")
        args.use_llm = False

    available = check_tools(args)

    # ── Step 1: subfinder ────────────────────────────────────────────────
    passive_subs = []
    passive_file = str(out_dir / "passive_subfinder.txt")
    if args.use_subfinder and "subfinder" in available:
        passive_subs = run_subfinder(domain, passive_file)
        if passive_subs:
            Path(passive_file).write_text("\n".join(passive_subs))

    if not Path(passive_file).exists() or not passive_subs:
        Path(passive_file).write_text(domain)
        if not args.use_subfinder or "subfinder" not in available:
            log("Seeding SubWiz input with base domain only (subfinder skipped)", "warn")

    # ── Step 2: SubWiz ───────────────────────────────────────────────────
    subwiz_subs = []
    subwiz_file = str(out_dir / "subwiz_predictions.txt")
    if args.use_subwiz and "subwiz" in available:
        subwiz_subs = run_subwiz(passive_file, subwiz_file, timeout=args.subwiz_timeout)
    elif args.use_subwiz:
        log("Skipping SubWiz — tool not available (pip install subwiz)", "warn")

    # Snapshot all known subs so far — passed to Claude for variant generation
    all_known_subs = sorted(set(passive_subs) | set(subwiz_subs))

    # ── Step 3: Website scraping ─────────────────────────────────────────
    site_text = ""
    if args.use_scrape:
        site_text = scrape_target(domain, fallback_subs=passive_subs)
        if site_text:
            (out_dir / "scraped_content.txt").write_text(site_text)

    # ── Step 4: NLTK keyword extraction ──────────────────────────────────
    nltk_words = []
    if args.use_nltk and site_text:
        nltk_words = nltk_keywords(site_text)
        if nltk_words:
            (out_dir / "nltk_keywords.txt").write_text("\n".join(nltk_words))

    # ── Step 5a: LLM contextual wordlist ─────────────────────────────────
    llm_words = []
    if args.use_llm and site_text:
        llm_words = llm_generate_wordlist(
            domain, site_text,
            known_subs=all_known_subs,   # <── Claude now sees discovered subs
            api_key=api_key, model=args.model
        )
        if llm_words:
            (out_dir / "llm_wordlist.txt").write_text("\n".join(llm_words))

    # ── Step 5b: LLM keyword enrichment ──────────────────────────────────
    enriched_words = []
    if args.use_llm and nltk_words:
        enriched_words = llm_enrich_keywords(nltk_words, domain,
                                              api_key=api_key, model=args.model)
        if enriched_words:
            (out_dir / "llm_enriched_keywords.txt").write_text("\n".join(enriched_words))

    # ── Step 6: Build combined wordlist ───────────────────────────────────
    combined = build_combined_wordlist(
        domain, passive_subs, subwiz_subs,
        nltk_words, llm_words, enriched_words
    )

    # ── Step 6b: Smart mutation engine ────────────────────────────────────
    # Runs after everything else so it has the full label set to work from.
    # Its own budget prevents it from exploding before the final cap.
    mutation_candidates: list[str] = []
    if args.use_mutate and combined:
        mutation_candidates = mutate_wordlist(combined, budget=args.mutation_budget)
        if mutation_candidates:
            (out_dir / "mutation_candidates.txt").write_text(
                "\n".join(mutation_candidates)
            )

    # Merge, then apply the hard final cap
    combined = sorted(set(combined) | set(mutation_candidates))
    combined = cap_wordlist(combined, limit=args.wordlist_max)

    combined_file = out_dir / "combined_wordlist.txt"
    combined_file.write_text("\n".join(combined))
    log(f"Final wordlist: {len(combined)} entries → {combined_file}", "ok")

    if args.wordlist_only:
        log("--wordlist-only flag set; skipping DNS resolution.", "info")
        print_summary(domain, passive_subs, subwiz_subs, mutation_candidates, [], out_dir)
        return

    # ── Step 7: puredns ───────────────────────────────────────────────────
    resolved_subs = passive_subs.copy()
    if args.use_puredns and "puredns" in available and combined:
        resolvers_file = str(out_dir / "resolvers-trusted.txt")
        download_resolvers(resolvers_file)
        if Path(resolvers_file).exists():
            resolved_file = str(out_dir / "resolved_subdomains.txt")
            puredns_found = run_puredns(domain, str(combined_file),
                                         resolvers_file, resolved_file)
            all_found = sorted(set(passive_subs) | set(puredns_found))
            (out_dir / "all_subdomains.txt").write_text("\n".join(all_found))
            resolved_subs = all_found
        else:
            log("Skipping puredns — resolvers file unavailable", "warn")

    # ── Step 8: httpx ─────────────────────────────────────────────────────
    if args.use_httpx and "httpx" in available and resolved_subs:
        all_subs_file = out_dir / "all_subdomains.txt"
        if not all_subs_file.exists():
            all_subs_file.write_text("\n".join(resolved_subs))
        run_httpx(str(all_subs_file), str(out_dir / "httpx_results.json"))

    # ── Final summary ─────────────────────────────────────────────────────
    print_summary(domain, passive_subs, subwiz_subs,
                  mutation_candidates, resolved_subs, out_dir)

    final_file = out_dir / "all_subdomains.txt"
    if final_file.exists():
        print(f"{BOLD}Live/resolved subdomains:{RESET}")
        for sub in final_file.read_text().splitlines():
            print(f"  {GREEN}{sub}{RESET}")


if __name__ == "__main__":
    main()
