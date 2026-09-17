import argparse
import io
import json
import os
import logging
import random
import re
import sys
import zipfile
import csv
import hashlib
import shutil
import subprocess
import collections.abc
import difflib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import requests
import time

def load_local_env() -> None:
    """Load variables from a local .env file when present."""
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


# Called here (not just inside main()/generate_with_llama() like before) so
# .env is loaded before OLLAMA_URL/OLLAMA_CHAT_TIMEOUT are read below --
# load_local_env() only sets a var if it's not already set, so the later
# calls are harmless no-ops once this has run. Safe to call at import time:
# it only reads a file next to this script, no network/process side effects.
load_local_env()

try:
    import ollama
    # ollama.chat() (the bare module function) has no per-call timeout --
    # a hung cloud-relayed model would stall a batch, and the whole
    # classification phase behind it, indefinitely with no way to notice
    # except by hand. Build our own client with one instead.
    OLLAMA_CHAT_TIMEOUT = float(os.getenv("OLLAMA_CHAT_TIMEOUT", "180"))
    _ollama_client = ollama.Client(host=os.getenv("OLLAMA_URL") or None, timeout=OLLAMA_CHAT_TIMEOUT)
    ollama_chat = _ollama_client.chat
except Exception:
    ollama_chat = None

try:
    import dns.resolver
except Exception:
    dns = None

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s:%(name)s:%(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# Global env variables
BATCH_SIZE = 500

# Models classified in parallel each run; a domain only lands in the
# stricter consensus list (blocklist_consensus.txt) if every model here
# agrees on both the domain and its category. Override via LLAMA_MODELS
# (comma-separated) in .env.
DEFAULT_MODELS = ["gemma4:31b-cloud", "nemotron-3-super:cloud"]

# Used to look up nameservers for the flagged-domains log. Queried directly
# rather than through the system resolver, since this machine also serves a
# DNS blocklist -- resolving through it could sinkhole the very domains
# we're trying to fingerprint.
NAMESERVER_RESOLVER_IP = os.getenv("NAMESERVER_RESOLVER_IP", "1.1.1.1")
NAMESERVER_LOOKUP_WORKERS = 40
NAMESERVER_LOOKUP_TIMEOUT = 3.0

# Known ad/tracking server list, merged into both blocklists "no questions
# asked" the same way the compromised-domains feed is -- entirely outside
# the LLM classification scan. Peter Lowe's list: plain domain-per-line,
# no API key needed, actively maintained, low false-positive rate. Override
# via AD_LIST_URL in .env.
AD_LIST_URL = os.getenv(
    "AD_LIST_URL",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext",
)


def get_configured_models():
    raw = os.getenv("LLAMA_MODELS", "")
    models = [m.strip() for m in raw.split(",") if m.strip()]
    return models or DEFAULT_MODELS

# Real feed archives run ~3-6MB (domains) / ~32MB (compromised) uncompressed;
# this caps decompression at a generous multiple of that so a
# compromised/spoofed upstream can't OOM the process with a decompression
# bomb -- a small compressed payload that expands to gigabytes in memory.
MAX_ARCHIVE_MEMBER_BYTES = 200 * 1024 * 1024

# Set at start of main() to filter files created during this run
RUN_START = None

# Track files created during this run (absolute Paths)
CREATED_FILES = set()


def register_created(path: Path) -> None:
    try:
        CREATED_FILES.add(path.resolve())
    except Exception:
        try:
            CREATED_FILES.add(Path(path))
        except Exception:
            pass


def retry_with_backoff(fn, is_transient, max_attempts=5, base_delay=2.0, jitter=True, on_retry=None):
    """Call fn() (a zero-arg callable) up to max_attempts times, retrying
    only exceptions is_transient(exc) says are worth retrying, with
    exponential backoff between attempts. Raises the final attempt's
    exception either way (transient-but-exhausted, or not transient at
    all) -- callers decide what to do with that themselves, same as
    before this was factored out of three near-identical retry loops
    (Ollama chat calls, feed HTTP fetches, the git push)."""
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except Exception as e:
            if is_transient(e) and attempt < max_attempts:
                delay = base_delay * (2 ** (attempt - 1))
                if jitter:
                    delay += random.uniform(0, 1)
                if on_retry:
                    on_retry(attempt, max_attempts, delay, e)
                time.sleep(delay)
                continue
            raise


def _extract_text_from_response(data):
    if not isinstance(data, dict):
        if hasattr(data, "dict") and callable(data.dict):
            try:
                data = data.dict(exclude_none=True)
            except Exception:
                pass
        if not isinstance(data, dict) and hasattr(data, "_asdict"):
            try:
                data = data._asdict()
            except Exception:
                pass
        if not isinstance(data, dict) and hasattr(data, "__dict__"):
            try:
                data = vars(data)
            except Exception:
                pass

    def _coerce_to_dict(value):
        if isinstance(value, dict):
            return value
        if hasattr(value, "dict") and callable(value.dict):
            try:
                return value.dict(exclude_none=True)
            except Exception:
                return {}
        if hasattr(value, "_asdict"):
            try:
                return value._asdict()
            except Exception:
                return {}
        if hasattr(value, "__dict__"):
            return vars(value)
        return {}

    def _extract_from_value(value):
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, (list, tuple)):
            parts = []
            for item in value:
                extracted = _extract_from_value(item)
                if extracted:
                    parts.append(extracted)
            return "\n".join(parts).strip()
        if isinstance(value, dict):
            for key in ("generated_text", "text", "result", "output", "content"):
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.strip()
                extracted = _extract_from_value(candidate)
                if extracted:
                    return extracted

            message = value.get("message")
            if message is not None:
                extracted = _extract_from_value(message)
                if extracted:
                    return extracted

            choices = value.get("choices")
            if isinstance(choices, list) and choices:
                for choice in choices:
                    extracted = _extract_from_value(choice)
                    if extracted:
                        return extracted

            for key in ("thinking", "reasoning"):
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.strip()

            return ""

        if hasattr(value, "content"):
            return _extract_from_value(getattr(value, "content"))
        if hasattr(value, "text"):
            return _extract_from_value(getattr(value, "text"))
        return ""

    if isinstance(data, dict):
        for key in ("generated_text", "text", "result", "output"):
            extracted = _extract_from_value(data.get(key))
            if extracted:
                return extracted

        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            for choice in choices:
                extracted = _extract_from_value(choice)
                if extracted:
                    return extracted

        message = data.get("message")
        extracted = _extract_from_value(message)
        if extracted:
            return extracted

    extracted = _extract_from_value(data)
    return extracted


def generate_with_llama(prompt: str, max_tokens: int = 1000, system_prompt: str = None, response_format=None, model_name: str = None) -> str:
    """Generate text using the local Ollama chat API.

    response_format, when given a JSON schema dict, asks Ollama to constrain
    the model's output to that shape. For models Ollama runs locally this is
    a hard grammar constraint; for cloud-relayed models it's only as strong
    as the remote backend's own structured-output support (verified
    empirically per-model, not guaranteed by the API itself).
    """
    load_local_env()

    model_name = model_name or os.getenv("LLAMA_MODEL_NAME", "gemma4:12b")
    if ollama_chat is None:
        raise RuntimeError(
            "No Ollama chat client is available. Install the ollama package and ensure the local Ollama service is running."
        )

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    def call():
        response = ollama_chat(
            model=model_name,
            messages=messages,
            think=False,
            stream=False,
            format=response_format,
            options={"num_predict": max_tokens},
        )
        if isinstance(response, collections.abc.Iterator) or isinstance(response, (list, tuple)):
            response = list(response)
            response = response[-1] if response else None

        content = getattr(getattr(response, "message", None), "content", None)
        if isinstance(content, str) and content.strip():
            return content.strip()

        content = _extract_text_from_response(response)
        if isinstance(content, str) and content.strip():
            return content.strip()

        raise RuntimeError(
            f"Ollama chat returned no usable response content: {content!r}. "
            f"Response type: {type(response).__name__}, response repr: {repr(response)}"
        )

    # Only retry errors that look transient (server overload, 5xx, timeouts,
    # connection hiccups). A 4xx like "model not found" will never succeed
    # no matter how many times we retry it.
    def is_transient(e):
        status_code = getattr(e, "status_code", None)
        return status_code is None or status_code >= 500

    def on_retry(attempt, max_attempts, delay, e):
        status_code = getattr(e, "status_code", None)
        log.warning(
            f"Ollama chat call failed on attempt {attempt}/{max_attempts} "
            f"(status_code={status_code}): {e}. Retrying in {delay:.1f}s..."
        )

    try:
        return retry_with_backoff(call, is_transient, max_attempts=5, base_delay=2.0, on_retry=on_retry)
    except Exception as e:
        raise RuntimeError(
            f"Ollama chat failed after retrying: {e}. Install and run the Ollama "
            f"service locally and ensure the model '{model_name}' is available."
        ) from None


CLASSIFICATION_CATEGORIES = [
    "Scams/Phishing",
    "Typosquatting",
    "Gambling",
    "Malware/C2",
    "Ads",
    "Tracking/Analytics",
    "Cryptojacking",
    "AI Deepfake/Impersonation",
]

_CATEGORY_LOOKUP = {c.lower(): c for c in CLASSIFICATION_CATEGORIES}


def _normalize_category(category):
    """Return the canonical category name for a possibly-slightly-off model
    response, or None if it doesn't resemble any real category closely
    enough to trust. Despite the schema enum, this isn't just theoretical:
    a real run produced "Gambing" (missing the 'l') that sailed through
    uncaught into a category breakdown. Exact match (case-insensitive)
    first; otherwise a close-match fuzzy check catches a typo like that
    without accepting something that isn't actually one of our categories."""
    if not category:
        return None
    exact = _CATEGORY_LOOKUP.get(category.strip().lower())
    if exact:
        return exact
    close = difflib.get_close_matches(category.strip().lower(), _CATEGORY_LOOKUP.keys(), n=1, cutoff=0.8)
    return _CATEGORY_LOOKUP[close[0]] if close else None

# Requests the model constrain its output to this exact shape, eliminating
# narration/preamble (see generate_with_llama docstring re: cloud vs local
# enforcement strength). The category enum also normalizes labels that used
# to vary ("Gambling" vs "Gambling sites") across responses.
FLAGGED_DOMAINS_SCHEMA = {
    "type": "object",
    "properties": {
        "flagged": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "category": {"type": "string", "enum": CLASSIFICATION_CATEGORIES},
                },
                "required": ["domain", "category"],
            },
        }
    },
    "required": ["flagged"],
}


def classify_batch(batch, model_name: str = None):
    categories_line = ", ".join(CLASSIFICATION_CATEGORIES)
    system_prompt = (
        "You are a domain name threat classifier. You analyze lists of newly registered domains and flag any that appear in these categories:\n"
        "- Scams/Phishing (e.g. paypa1-secure.com, amazon-login-verify.net)\n"
        "- Typosquatting of well-known brands (e.g. gooogle.com, arnazon.com)\n"
        "- Gambling sites (e.g. online-casino.net, bet365-login.com)\n"
        "- Malware distribution or potential C2 (e.g. malware-download.com, c2-server.net)\n"
        "- Ads (e.g. adsrvs.com, adclicks.net)\n"
        "- Tracking or analytics (e.g. trackingpixel.com, analytics-service.net)\n"
        "- Cryptojacking (e.g. cryptomining.com, coin-hive.com)\n"
        "- AI Deepfake or impersonation (e.g. deepfake-celebrity.com, fake-ai-avatar.net)\n\n"
        'Respond with JSON matching the given schema: {"flagged": [{"domain": "...", "category": "..."}]}.\n'
        "Use ONLY these exact category values: " + categories_line + ".\n"
        "Only include a domain if it has a confidence score of 0.9 or higher for one of the categories above.\n"
        'If none qualify, respond with {"flagged": []}.\n'
        "Output compact, minified JSON on a single line with no pretty-printing, indentation, or extra "
        "whitespace/newlines inside the JSON. Every token spent on formatting is a token not spent on "
        "another flagged domain."
    )

    user_input = chr(10).join(batch)
    resp_text = generate_with_llama(
        user_input,
        max_tokens=6000,
        system_prompt=system_prompt,
        response_format=FLAGGED_DOMAINS_SCHEMA,
        model_name=model_name,
    )

    batch_domains = {d.strip().lower() for d in batch}

    # Some providers wrap structured-output JSON in a markdown code fence
    # even when a schema was requested -- strip it before parsing.
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", resp_text.strip(), re.DOTALL)
    json_text = fenced.group(1) if fenced else resp_text

    try:
        # Parse just the first complete JSON value and ignore anything the
        # model appended after it (some responses trail off into extra
        # commentary or a repeated block past the closing brace) rather than
        # requiring the entire response to be pure JSON via json.loads().
        parsed, _ = json.JSONDecoder().raw_decode(json_text.lstrip())
        rows = parsed.get("flagged", []) if isinstance(parsed, dict) else []
    except json.JSONDecodeError as e:
        # Usually means the response got cut off mid-array by hitting
        # max_tokens before the model could close out the JSON.
        log.warning(
            "Batch response was not valid JSON despite requesting structured "
            "output (likely truncated by num_predict): %s. Raw response "
            "(first 500 chars): %r",
            e, resp_text[:500],
        )
        return []

    flagged = []
    rejected = 0
    first_rejected = None
    for row in rows:
        domain = str(row.get("domain", "")).strip().lower() if isinstance(row, dict) else ""
        raw_category = str(row.get("category", "")).strip() if isinstance(row, dict) else ""
        category = _normalize_category(raw_category)
        # Only trust rows naming a domain that was actually in this batch --
        # anything else is a hallucinated/misremembered domain, not a real
        # classification of the input we sent.
        if domain and category and is_valid_domain(domain) and domain in batch_domains:
            if category != raw_category:
                log.info("Normalized model category %r to %r for %s", raw_category, category, domain)
            flagged.append({"domain": domain, "category": category})
        else:
            rejected += 1
            if first_rejected is None:
                first_rejected = row

    if rows:
        reject_rate = rejected / len(rows)
        if rejected >= 5 and reject_rate >= 0.5:
            log.warning(
                "Batch response had %d/%d (%.0f%%) entries rejected: not a real "
                "domain from this batch. First rejected entry: %r",
                rejected, len(rows), reject_rate * 100, first_rejected,
            )

    return flagged


def count_categories(flagged):
    counts = Counter()
    for entry in flagged:
        counts[entry["category"].strip()] += 1
    return counts


def classify_domains(domains, model_name: str = None):
    resolved_model = model_name or os.getenv("LLAMA_MODEL_NAME", "gemma4:12b")
    all_flagged = []
    zero_flag_batches = 0
    failed_batches = 0
    total_batches = (len(domains) + BATCH_SIZE - 1) // BATCH_SIZE

    for i in range(0, len(domains), BATCH_SIZE):
        batch = domains[i:i + BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        try:
            flagged = classify_batch(batch, model_name=resolved_model)
        except Exception as e:
            # A batch that fails every retry (e.g. a cloud backend having a
            # bad day on one model) shouldn't take down the whole run --
            # especially now that a second model's already-completed work
            # would otherwise be thrown away with it. Skip it, count it, and
            # keep going; the run still completes and pushes what it got.
            failed_batches += 1
            flagged = []
            log.warning(f"[{resolved_model}] Batch {batch_num}/{total_batches} failed, skipping: {e}")
        for entry in flagged:
            entry["model"] = resolved_model
        all_flagged.extend(flagged)
        if not flagged:
            zero_flag_batches += 1
        log.info(f"[{resolved_model}] Batch {batch_num}/{total_batches}: {len(flagged)} flagged")

    log.info(f"[{resolved_model}] Total flagged: {len(all_flagged):,}")
    if failed_batches:
        log.warning(f"[{resolved_model}] {failed_batches}/{total_batches} batches failed and were skipped.")

    category_counts = count_categories(all_flagged)
    if category_counts:
        log.info(f"[{resolved_model}] Category breakdown:")
        for category, count in category_counts.most_common():
            log.info(f"  {category}: {count:,}")

    if total_batches >= 3:
        zero_flag_rate = zero_flag_batches / total_batches
        if zero_flag_rate >= 0.8:
            log.warning(
                "[%s] %d/%d batches (%.0f%%) returned zero flagged domains this run. "
                "That's unusual for this feed -- treat this as a likely classifier "
                "failure (truncated responses, bad model config, etc.) rather than "
                "assuming today's batch was unusually clean, and check the run's logs.",
                resolved_model, zero_flag_batches, total_batches, zero_flag_rate * 100,
            )

    stats = {
        "total_batches": total_batches,
        "zero_flag_batches": zero_flag_batches,
        "failed_batches": failed_batches,
        "category_counts": category_counts,
    }
    return all_flagged, stats


def _lookup_nameservers(domain, resolver):
    try:
        answer = resolver.resolve(domain, "NS")
        return "; ".join(sorted(str(rdata.target).rstrip(".").lower() for rdata in answer))
    except Exception:
        # NXDOMAIN, no NS records, timeout, etc. -- newly registered domains
        # routinely haven't propagated yet or never resolve at all. Not
        # worth distinguishing the failure modes here; an empty nameserver
        # is itself a signal (unregistered/parked/dead by lookup time).
        return ""


def resolve_nameservers(domains):
    """Look up the authoritative nameservers for each domain, concurrently,
    against a public resolver (see NAMESERVER_RESOLVER_IP). Returns
    {domain: "ns1.example.com; ns2.example.com"}, with "" for domains that
    didn't resolve. Missing dnspython degrades to "" for every domain rather
    than failing the run -- same pattern as the optional ollama import."""
    domains = sorted(domains)
    if not domains:
        return {}

    if dns is None:
        log.warning(
            "dnspython not installed; skipping nameserver lookups for %d domains "
            "(pip install dnspython to enable).", len(domains),
        )
        return {domain: "" for domain in domains}

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [NAMESERVER_RESOLVER_IP]
    resolver.timeout = NAMESERVER_LOOKUP_TIMEOUT
    resolver.lifetime = NAMESERVER_LOOKUP_TIMEOUT

    results = {}
    with ThreadPoolExecutor(max_workers=NAMESERVER_LOOKUP_WORKERS) as executor:
        futures = {executor.submit(_lookup_nameservers, domain, resolver): domain for domain in domains}
        for future in as_completed(futures):
            domain = futures[future]
            results[domain] = future.result()

    resolved = sum(1 for ns in results.values() if ns)
    log.info(f"Resolved nameservers for {resolved:,}/{len(domains):,} flagged domains.")
    return results


def classify_domains_multi(domains, model_names):
    """Run classification against every model in model_names over the same
    domain list.

    Returns:
      - per_model: {model_name: {"flagged": [...], "stats": {...}}}
      - all_flagged: every (domain, category, model) row from every model --
        the union, used for List 1 (blocklist.txt) and the flagged-domains log.
      - consensus_flagged: only domains where every configured model assigned
        the *same* category, used for List 2 (blocklist_consensus.txt) to
        filter out single-model hallucinations.
    """
    per_model = {}
    for model_name in model_names:
        flagged, stats = classify_domains(domains, model_name=model_name)
        per_model[model_name] = {"flagged": flagged, "stats": stats}

    all_flagged = [entry for result in per_model.values() for entry in result["flagged"]]

    votes = {}
    for entry in all_flagged:
        votes.setdefault(entry["domain"], {}).setdefault(entry["category"], set()).add(entry["model"])

    consensus_flagged = []
    required = set(model_names)
    for domain, category_votes in votes.items():
        for category, models in category_votes.items():
            if models >= required:
                consensus_flagged.append({"domain": domain, "category": category, "models": sorted(models)})

    log.info(
        f"Consensus: {len(consensus_flagged):,} domains agreed on by all {len(model_names)} model(s), "
        f"out of {len({e['domain'] for e in all_flagged}):,} flagged by at least one."
    )

    return per_model, all_flagged, consensus_flagged


def logs_subdir(name):
    subdir = Path("logs") / name
    subdir.mkdir(parents=True, exist_ok=True)
    return subdir


def sanitize_csv_field(value):
    """Defuse CSV/formula injection (OWASP-style): prefix values that a
    spreadsheet app (Excel, Sheets) would interpret as a formula with a
    leading single quote. The "domain" column is already restricted to
    [a-z0-9-.] by is_valid_domain() and never needs this, but "category"
    text comes straight from the LLM's response with no character
    restrictions, so it gets sanitized here at the point of CSV output only
    -- the JSON logs keep the raw, unmodified value."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def write_daily_log(flagged, when: datetime = None):
    now = when or datetime.now()

    csv_path = make_unique_timestamped_path(logs_subdir("csv"), "flagged_domains", "csv", now)
    json_path = make_unique_timestamped_path(logs_subdir("json"), "flagged_domains", "json", now)

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["domain", "classification", "model", "nameserver"])
        writer.writeheader()
        for entry in flagged:
            writer.writerow({
                "domain": entry["domain"],
                "classification": sanitize_csv_field(entry["category"]),
                "model": sanitize_csv_field(entry.get("model", "")),
                "nameserver": sanitize_csv_field(entry.get("nameserver", "")),
            })

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(flagged, handle, indent=2)
        handle.write("\n")

    register_created(csv_path)
    register_created(json_path)
    log.info(f"Saved {len(flagged)} flagged entries to {csv_path} and {json_path}")
    return csv_path, json_path


def write_category_summary(flagged, when: datetime = None):
    now = when or datetime.now()

    csv_path = make_unique_timestamped_path(logs_subdir("csv"), "category_summary", "csv", now)
    json_path = make_unique_timestamped_path(logs_subdir("json"), "category_summary", "json", now)

    category_counts = count_categories(flagged)
    total = sum(category_counts.values())
    rows = [{"category": category, "count": count} for category, count in category_counts.most_common()]

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["category", "count"])
        writer.writeheader()
        for row in rows:
            writer.writerow({"category": sanitize_csv_field(row["category"]), "count": row["count"]})
        writer.writerow({"category": "TOTAL", "count": total})

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump({"total": total, "categories": rows}, handle, indent=2)
        handle.write("\n")

    register_created(csv_path)
    register_created(json_path)
    log.info(f"Saved category summary ({len(rows)} categories, {total:,} total) to {csv_path} and {json_path}")
    return csv_path, json_path


def write_classification_stats(per_model, when: datetime = None):
    """Persist per-model classification stats (batch counts, category
    breakdown) to a JSON sidecar, purely so a later `--resume` run can pick
    up exactly where a failed run left off (see load_resume_state()) without
    reconstructing this by replaying batch boundaries against the domain
    archive or scraping the cron log by hand -- both of which is what
    actually happened, more than once, before this existed."""
    now = when or datetime.now()
    path = make_unique_timestamped_path(logs_subdir("json"), "classification_stats", "json", now)
    serializable = {
        model_name: {
            "total_batches": result["stats"]["total_batches"],
            "zero_flag_batches": result["stats"]["zero_flag_batches"],
            "failed_batches": result["stats"]["failed_batches"],
            "category_counts": dict(result["stats"]["category_counts"]),
        }
        for model_name, result in per_model.items()
    }
    path.write_text(json.dumps(serializable, indent=2) + "\n", encoding="utf-8")
    register_created(path)
    log.info(f"Saved classification stats to {path}")
    return path


def _csv_sibling(json_path: Path) -> Path:
    """logs/json/<name>.json -> logs/csv/<name>.csv, the fixed layout every
    other log pair in this file already uses."""
    return json_path.parent.parent / "csv" / json_path.with_suffix(".csv").name


def load_resume_state(when: datetime):
    """For --resume: load a previously-completed classification for `when`
    (both a flagged_domains_<date> and a classification_stats_<date> log
    must exist -- the latter is only written going forward, so this can't
    resume a date from before write_classification_stats() existed). Returns
    None if either is missing, otherwise the parsed data plus every path
    involved, so main() can register_created() them: they were written by a
    run that died before reaching push_to_github(), so they exist on disk
    but were never actually committed."""
    date_str = when.strftime("%Y-%m-%d")
    json_dir = Path("logs") / "json"
    flagged_path = find_archive_for_date(json_dir, "flagged_domains", date_str, extension="json")
    stats_path = find_archive_for_date(json_dir, "classification_stats", date_str, extension="json")
    if flagged_path is None or stats_path is None:
        return None
    category_path = find_archive_for_date(json_dir, "category_summary", date_str, extension="json")

    all_flagged = json.loads(flagged_path.read_text(encoding="utf-8"))
    raw_stats = json.loads(stats_path.read_text(encoding="utf-8"))
    per_model_stats = {
        model_name: {
            "total_batches": s["total_batches"],
            "zero_flag_batches": s["zero_flag_batches"],
            "failed_batches": s["failed_batches"],
            "category_counts": Counter(s["category_counts"]),
        }
        for model_name, s in raw_stats.items()
    }

    paths = [flagged_path, stats_path]
    if category_path is not None:
        paths.append(category_path)
    for p in (flagged_path, category_path):
        if p is not None:
            csv_sibling = _csv_sibling(p)
            if csv_sibling.exists():
                paths.append(csv_sibling)

    return {"all_flagged": all_flagged, "per_model_stats": per_model_stats, "paths": paths}


def write_known_list_log(entries, when: datetime = None, prefix: str = "compromised_added", noun: str = "compromised"):
    """Log domains newly added to the blocklist(s) from a known/curated
    source (compromised feed, ad list, ...) -- not from LLM classification."""
    if not entries:
        log.info(f"No new {noun} domains to log")
        return None

    now = when or datetime.now()

    csv_path = make_unique_timestamped_path(logs_subdir("csv"), prefix, "csv", now)
    json_path = make_unique_timestamped_path(logs_subdir("json"), prefix, "json", now)

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["domain", "classification", "reason"])
        writer.writeheader()
        writer.writerows(entries)

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(entries, handle, indent=2)
        handle.write("\n")
    register_created(csv_path)
    register_created(json_path)
    log.info(f"Saved {len(entries)} newly added {noun} domains to {csv_path} and {json_path}")
    return csv_path, json_path


def write_daily_digest(
    total_domains_scanned,
    per_model,
    all_flagged,
    consensus_flagged,
    list1_total_after_classification,
    list2_total_after_classification,
    list1_final_total,
    list2_final_total,
    known_list_results,
    when: datetime = None,
    classification_skipped: bool = False,
):
    """known_list_results: {name: {"display_name": str, "fetched": int,
    "added": [...], "failed": bool}} -- one entry per known/curated source
    (compromised feed, ad list, ...) merged in outside the LLM scan. Takes
    this as one dict rather than a growing set of per-source positional
    params so a future third/fourth source is just another entry here
    instead of another parameter everywhere this is called."""
    now = when or datetime.now()
    digest_path = make_unique_timestamped_path(logs_subdir("daily_summary"), "daily_summary", "md", now)

    union_domain_count = len({entry["domain"] for entry in all_flagged})

    lines = [
        f"# NRDGuard Daily Summary -- {now.strftime('%Y-%m-%d')}",
        "",
        "## Domains Scanned",
        f"- Total domains fetched: {total_domains_scanned:,}",
        "",
    ]
    if classification_skipped:
        lines += [
            "_Classification skipped -- the domains feed was unchanged since the last run._",
            "",
        ]

    lines.append("## Classification Results by Model")
    for model_name, result in per_model.items():
        stats = result["stats"]
        lines += [
            f"### {model_name}",
            f"- Batches processed: {stats['total_batches']:,} ({stats['zero_flag_batches']:,} returned zero flagged domains, {stats.get('failed_batches', 0):,} failed and were skipped)",
            f"- Total flagged: {len(result['flagged']):,}",
            "",
            "| Category | Count |",
            "|---|---|",
        ]
        for category, count in stats["category_counts"].most_common():
            lines.append(f"| {category} | {count:,} |")
        lines.append("")

    lines += [
        "## Model Agreement",
        f"- Domains flagged by at least one model: {union_domain_count:,}",
        f"- Domains every model agreed on (domain + category): {len(consensus_flagged):,}",
        "",
    ]

    for result in known_list_results.values():
        lines += [
            f"## {result['display_name']} Feed",
            f"- Domains fetched: {result['fetched']:,}",
            f"- Newly added: {len(result['added']):,}",
            "",
        ]

    extra = "".join(f" + {r['display_name']}" for r in known_list_results.values())
    lines += [
        f"## List 1 -- blocklist.txt (union of all models{extra})",
        f"- After classification: {list1_total_after_classification:,} domains",
        f"- Final: {list1_final_total:,} domains",
        "",
        f"## List 2 -- blocklist_consensus.txt (model agreement{extra})",
        f"- After classification: {list2_total_after_classification:,} domains",
        f"- Final: {list2_final_total:,} domains",
        "",
    ]

    notes = []
    for result in known_list_results.values():
        if result["failed"]:
            notes.append(
                f"The {result['display_name'].lower()} fetch failed for this run (see the "
                "run's log) and was skipped rather than aborting the whole pipeline -- "
                "nothing was merged in from that source this time. Re-run that step for "
                "this date once the feed is reachable again."
            )
    if notes:
        lines.append("## Note")
        for note in notes:
            lines.append(note)
            lines.append("")

    digest_path.write_text("\n".join(lines), encoding="utf-8")
    register_created(digest_path)
    log.info(f"Saved daily digest to {digest_path}")
    return digest_path


def hash_file(path: Path) -> str:
    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def hash_bytes(data: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def is_valid_domain(entry: str) -> bool:
    candidate = entry.strip().lower()
    if not candidate:
        return False
    if candidate.startswith(('#', '*', '-')):
        return False
    if ' ' in candidate:
        return False
    if candidate.startswith('.') or candidate.endswith('.'):
        return False
    if '..' in candidate:
        return False

    labels = candidate.split('.')
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
        if not re.fullmatch(r'[a-z0-9-]+', label):
            return False

    return True


def make_unique_timestamped_path(directory: Path, prefix: str, extension: str, when: datetime = None) -> Path:
    when = when or datetime.now()
    base_name = f"{prefix}_{when.strftime('%Y-%m-%d')}"
    candidate = directory / f"{base_name}.{extension}"
    counter = 1
    while candidate.exists():
        candidate = directory / f"{base_name}_{counter}.{extension}"
        counter += 1
    return candidate


def find_latest_archive(archives_dir: Path, prefix: str, extension: str = "zip"):
    candidates = sorted(
        [path for path in archives_dir.glob(f"{prefix}_*.{extension}") if path.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def find_archive_for_date(archives_dir: Path, prefix: str, date_str: str, extension: str = "zip"):
    """Find the archive (or, with extension="json", a resume-state log)
    saved for a specific YYYY-MM-DD date.

    A day with more than one run leaves extra `_1`, `_2`, ... suffixed
    files (see make_unique_timestamped_path); this picks the most recent
    of those over the bare dated file, since it reflects the last state
    fetched that day.
    """
    exact = archives_dir / f"{prefix}_{date_str}.{extension}"
    reruns = sorted(
        archives_dir.glob(f"{prefix}_{date_str}_*.{extension}"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if reruns:
        return reruns[0]
    if exact.exists():
        return exact
    return None


def write_hash_file(path: Path, digest: str) -> Path:
    if path.name.endswith(".sha256"):
        return path

    hash_path = path.with_suffix(path.suffix + ".sha256")
    with hash_path.open("w", encoding="utf-8") as handle:
        handle.write(f"{digest}  {path.name}\n")
    register_created(hash_path)
    return hash_path


def hash_blocklist():
    files_to_hash = []
    repo_dir = Path(__file__).resolve().parent
    seen = set()
    # Only hash files explicitly registered as created during this run
    for p in sorted(CREATED_FILES):
        try:
            p = Path(p)
            if p.name.endswith(".sha256"):
                continue
            resolved = p.resolve()
            if resolved in seen:
                continue
            try:
                resolved.relative_to(repo_dir.resolve())
            except Exception:
                continue
            if p.exists() and p.is_file():
                files_to_hash.append(p)
                seen.add(resolved)
        except Exception:
            continue

    if not files_to_hash:
        log.info("No created files to hash for this run")
        return []

    hash_paths = []
    for path in files_to_hash:
        digest = hash_file(path)
        hash_path = write_hash_file(path, digest)
        hash_paths.append(hash_path)
        log.info(f"Wrote SHA-256 hash for {path} to {hash_path}")

    return hash_paths


def push_to_github():
    repo_dir = Path(__file__).resolve().parent
    blocklist_path = repo_dir / "blocklist.txt"
    consensus_blocklist_path = repo_dir / "blocklist_consensus.txt"
    logs_dir = repo_dir / "logs"
    # Only include .sha256 files that were created during this run
    sha_files = []
    seen_sha_files = set()
    for p in sorted(CREATED_FILES):
        try:
            path = Path(p)
            if not path.exists() or not path.is_file() or not path.name.endswith(".sha256"):
                continue
            resolved = path.resolve()
            if resolved in seen_sha_files:
                continue
            try:
                resolved.relative_to(repo_dir.resolve())
            except Exception:
                continue
            sha_files.append(path)
            seen_sha_files.add(resolved)
        except Exception:
            continue

    # try to enable Git LFS and track both blocklists to avoid pushing >25MB files
    try:
        subprocess.run(["git", "-C", str(repo_dir), "lfs", "install"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["git", "-C", str(repo_dir), "lfs", "track", "blocklist.txt"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["git", "-C", str(repo_dir), "lfs", "track", "blocklist_consensus.txt"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # `git lfs track` rewrites .gitattributes on disk but nothing else
        # registers that change, so without this it silently never gets
        # committed and LFS tracking for new patterns never actually takes
        # effect on the remote.
        register_created(repo_dir / ".gitattributes")
    except subprocess.CalledProcessError as exc:
        log.warning("git lfs setup failed or not available: %s", exc)

    token = os.getenv("GITHUB_TOKEN")
    repo_url = os.getenv("GITHUB_REPO","Jovock1/NRDGuard")
    branch = os.getenv("GITHUB_BRANCH", "main")

    if not token or not repo_url:
        log.warning("GITHUB_TOKEN or GITHUB_REPO not set; skipping GitHub push")
        return None

    if not blocklist_path.exists():
        log.warning("blocklist.txt not found; skipping GitHub push")
        return None

    if shutil.which("git") is None:
        log.warning("git is not installed or not on PATH; skipping GitHub push")
        return None

    if not logs_dir.exists():
        logs_dir.mkdir(exist_ok=True)

    # Build the files-to-add list from CREATED_FILES only
    files_to_add = []
    repo_dir_resolved = repo_dir.resolve()
    for p in sorted(CREATED_FILES):
        try:
            p = Path(p)
            if not p.exists():
                continue
            try:
                p.resolve().relative_to(repo_dir_resolved)
            except Exception:
                continue
            files_to_add.append(p)
        except Exception:
            continue
    # include sha files that were created (dedupe)
    for p in sha_files:
        if p.exists() and p not in files_to_add:
            files_to_add.append(p)

    # Always include both blocklists and their hashes if present (primary artifacts)
    try:
        if blocklist_path.exists() and blocklist_path.resolve() not in files_to_add:
            files_to_add.insert(0, blocklist_path)
        blocklist_sha = repo_dir / (blocklist_path.name + ".sha256")
        if blocklist_sha.exists() and blocklist_sha.resolve() not in files_to_add:
            files_to_add.insert(1, blocklist_sha)
        if consensus_blocklist_path.exists() and consensus_blocklist_path.resolve() not in files_to_add:
            files_to_add.append(consensus_blocklist_path)
        consensus_sha = repo_dir / (consensus_blocklist_path.name + ".sha256")
        if consensus_sha.exists() and consensus_sha.resolve() not in files_to_add:
            files_to_add.append(consensus_sha)
    except Exception:
        pass

    # include .gitattributes only if it was created this run
    gitattributes = repo_dir / ".gitattributes"
    try:
        if gitattributes.exists() and gitattributes.resolve() in CREATED_FILES:
            files_to_add.append(gitattributes)
    except Exception:
        pass

    files_to_add = [path for path in files_to_add if path.exists()]

    try:
        subprocess.run(["git", "-C", str(repo_dir), "init"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        pass

    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "DomainBot"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "domainbot@example.com"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    subprocess.run(["git", "-C", str(repo_dir), "add", *[str(path) for path in files_to_add]], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # commit only if there are changes
    try:
        subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "Update blocklist and logs"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        log.info("No changes to commit")

    # The remote URL deliberately never embeds the token -- a token-bearing
    # URL would get written to .git/config in plaintext (and that file is
    # commonly world-readable), and would also appear verbatim in any
    # CalledProcessError raised against a command referencing it. Credentials
    # are instead supplied only to the `push` invocation below, via a
    # transient credential helper that reads GITHUB_TOKEN from the process
    # environment at git's invocation time -- the secret itself never touches
    # disk or any command's argv.
    remote_url = f"https://github.com/{repo_url}.git"
    # set remote if not present
    try:
        subprocess.run(["git", "-C", str(repo_dir), "remote", "add", "origin", remote_url], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        # remote may already exist; set-url to be safe
        try:
            subprocess.run(["git", "-C", str(repo_dir), "remote", "set-url", "origin", remote_url], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as exc:
            log.warning("Unable to configure Git remote origin: %s", exc)
            return None

    credential_helper = '!f() { echo username=x-access-token; echo "password=$GITHUB_TOKEN"; }; f'
    push_env = os.environ.copy()
    push_env["GITHUB_TOKEN"] = token

    # Network-flap markers seen from this machine's VPN dropping mid-push
    # (kill switch blocks all traffic while it reconnects) -- distinct from
    # a real git error (auth failure, non-fast-forward, LFS quota) that
    # retrying can't fix.
    TRANSIENT_GIT_MARKERS = (
        "could not resolve host",
        "connection timed out",
        "connection refused",
        "network is unreachable",
        "could not connect to server",
        "ssl connection",
        "operation timed out",
        "the requested url returned error: 5",
    )

    def call():
        subprocess.run(
            ["git", "-C", str(repo_dir), "-c", f"credential.helper={credential_helper}", "push", "-u", "origin", branch],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=push_env,
        )

    def _stderr_of(e):
        return e.stderr.decode("utf-8", "replace").strip() if getattr(e, "stderr", None) else ""

    def is_transient(e):
        return any(marker in _stderr_of(e).lower() for marker in TRANSIENT_GIT_MARKERS)

    def on_retry(attempt, max_attempts, delay, e):
        log.warning(
            "Git push failed on attempt %d/%d (looks transient -- VPN/network blip): %s. "
            "Retrying in %.0fs...", attempt, max_attempts, _stderr_of(e) or e, delay,
        )

    try:
        # exc's command/stdout/stderr never contain the token itself (only
        # the literal string "$GITHUB_TOKEN", resolved by the nested shell
        # at runtime, not by this process), so this is safe to log as-is.
        # str(exc) alone omits stdout/stderr, which is where git's actual
        # reason (auth failure, non-fast-forward, LFS error, etc.) lives --
        # log those explicitly or every failure just says "exit status 1".
        retry_with_backoff(call, is_transient, max_attempts=5, base_delay=5.0, jitter=False, on_retry=on_retry)
    except subprocess.CalledProcessError as exc:
        stderr = _stderr_of(exc)
        stdout = exc.stdout.decode("utf-8", "replace").strip() if exc.stdout else ""
        log.warning("Git push failed: %s", exc)
        if stderr:
            log.warning("git stderr: %s", stderr)
        if stdout:
            log.warning("git stdout: %s", stdout)
        log.warning(
            "Skipping GitHub push and continuing without failing the entire pipeline "
            "-- the commit is safe locally and the next run will push it automatically."
        )
        return None

    log.info("Pushed blocklist, logs, and hashes to GitHub")
    return True


def get_api_key():
    log.info("Fetching API Key for URL API")
    URL_API_KEY = os.getenv('URL_API_KEY', '0')
    if URL_API_KEY == '0':
        log.error("URL_API_KEY environment variable not set")
        raise ValueError("URL_API_KEY environment variable not set")


def fetch_url(url, secrets, timeout=120):
    """GET a URL and raise_for_status(), redacting any of the given secret
    substrings out of the error message before re-raising.

    These feed URLs embed their API key directly (the APIs don't support
    sending it via a header instead), and requests' exception messages
    include the full request URL -- without this, a failed request would
    write the live API key in cleartext to the pipeline's logs via main()'s
    generic exception handler.

    Retries transient failures (connection errors, timeouts, 5xx) with
    exponential backoff, same pattern as generate_with_llama's Ollama
    retries -- domains-monitor.com has repeatedly dropped the connection on
    this call specifically, well into a run, and previously took down the
    entire pipeline (losing ~2 hours of already-completed classification)
    for what turned out to be a several-second blip. A 4xx (bad key, not
    found) is never worth retrying.
    """
    def redact(text):
        for secret in secrets:
            if secret:
                text = text.replace(secret, "***REDACTED***")
        return text

    def call():
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r

    def is_transient(e):
        status_code = getattr(getattr(e, "response", None), "status_code", None)
        return status_code is None or status_code >= 500

    def on_retry(attempt, max_attempts, delay, e):
        status_code = getattr(getattr(e, "response", None), "status_code", None)
        log.warning(
            f"Request failed on attempt {attempt}/{max_attempts} "
            f"(status_code={status_code}): {redact(str(e))}. Retrying in {delay:.1f}s..."
        )

    try:
        return retry_with_backoff(call, is_transient, max_attempts=5, base_delay=3.0, on_retry=on_retry)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Request failed: {redact(str(e))}") from None


def read_zip_member_text(archive_bytes, max_size=MAX_ARCHIVE_MEMBER_BYTES):
    """Decompress the first member of a zip archive to text, refusing to
    buffer more than max_size bytes into memory.

    zipfile.read() has no size cap of its own -- it'll happily decompress an
    arbitrarily large payload from a tiny compressed file (a "zip bomb").
    The zip's own declared uncompressed size is just metadata a malicious
    archive could lie about, so this streams the read in chunks and checks
    the running total itself rather than trusting that field.
    """
    z = zipfile.ZipFile(io.BytesIO(archive_bytes))
    name = z.namelist()[0]
    chunks = []
    total = 0
    with z.open(name) as member:
        while True:
            chunk = member.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_size:
                raise ValueError(
                    f"Refusing to decompress '{name}': exceeded {max_size:,} byte limit "
                    f"(possible decompression bomb from a compromised feed)"
                )
            chunks.append(chunk)
    return b"".join(chunks).decode()


def fetch_domains(for_date: datetime = None):
    """Returns the domain list, or None if the live feed is byte-identical
    to the last archive (nothing new to classify). None is a deliberate
    sentinel, not sys.exit(0) -- that used to kill the whole process here,
    which also skipped the independent compromised/ad-list merges and the
    push for the day. main() now treats None as "skip classification only"
    and still runs everything else."""
    repo_dir = Path(__file__).resolve().parent
    archives_dir = repo_dir / "archives"
    archives_dir.mkdir(exist_ok=True)

    if for_date is not None:
        date_str = for_date.strftime("%Y-%m-%d")
        archive_path = find_archive_for_date(archives_dir, "domains", date_str)
        if archive_path is None:
            raise FileNotFoundError(
                f"No domains archive found for {date_str} in {archives_dir}"
            )
        log.info(f"Replaying domains archive {archive_path}")
        domains = read_zip_member_text(archive_path.read_bytes()).splitlines()
        domains = [d.strip().lower() for d in domains if d.strip()]
        log.info(f"Loaded {len(domains):,} domains.")
        return domains

    log.info("Fetching domains from API")
    APICall = os.getenv('API_CALL', '0')
    if APICall == '0':
        log.error("API_CALL environment variable not set")
        raise ValueError("API_CALL environment variable not set")
    URL_API_KEY = os.getenv('URL_API_KEY', '0')
    if URL_API_KEY == '0':
        log.error("URL_API_KEY environment variable not set")
        raise ValueError("URL_API_KEY environment variable not set")

    DAILY_UPDATE = os.getenv('DAILY', '0')
    if DAILY_UPDATE == '0':
        log.error("DAILY environment variable not set")
        raise ValueError("DAILY environment variable not set")

    latest_archive = find_latest_archive(archives_dir, "domains")
    url = f"{APICall}{URL_API_KEY}{DAILY_UPDATE}"
    r = fetch_url(url, secrets=[URL_API_KEY])
    archive_bytes = r.content
    archive_hash = hash_bytes(archive_bytes)

    if latest_archive is not None:
        latest_hash = hash_file(latest_archive)
        log.info(f"Latest local domains archive: {latest_archive} ({latest_hash})")
        if archive_hash == latest_hash:
            log.info("Domains feed has not changed since the last archive; nothing new to classify.")
            return None

    now = datetime.now()
    archive_path = make_unique_timestamped_path(archives_dir, "domains", "zip", now)
    archive_path.write_bytes(archive_bytes)
    log.info(f"Saved downloaded archive to {archive_path} (hash {archive_hash})")

    domains = read_zip_member_text(archive_bytes).splitlines()
    domains = [d.strip().lower() for d in domains if d.strip()]
    log.info(f"Fetched {len(domains):,} domains.")
    return domains


def load_valid_domains(path: Path) -> set:
    """Read a blocklist file into a set of valid domains, dropping anything
    that doesn't pass is_valid_domain() (stray comments, blank lines,
    malformed entries from some earlier bug, etc.)."""
    domains = set()
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                cleaned = line.strip().lower()
                if is_valid_domain(cleaned):
                    domains.add(cleaned)
    return domains


def write_blocklist(path: Path, domains) -> int:
    with path.open("w", encoding="utf-8") as handle:
        for domain in sorted(domains):
            handle.write(f"{domain}\n")
    register_created(path)
    log.info(f"{path} written. Total domains: {len(domains):,}")
    return len(domains)


def add_to_blocklist(flagged, blocklist_path: Path = None):
    # Kept as a single read-modify-write convenience function for anything
    # calling it standalone (a one-off script, a manual resume) -- main()
    # itself uses load_valid_domains()/write_blocklist() directly instead,
    # so a run merging several sources into the same blocklist reads and
    # rewrites the file once each rather than once per source.
    blocklist_path = blocklist_path or Path("blocklist.txt")
    log.info(f"Adding flagged domains to {blocklist_path}")
    existing_domains = load_valid_domains(blocklist_path)
    new_domains = {entry["domain"] for entry in flagged if is_valid_domain(entry["domain"])}
    combined_domains = existing_domains.union(new_domains)
    return write_blocklist(blocklist_path, combined_domains)


def fetch_compromised_domains(for_date: datetime = None):
    repo_dir = Path(__file__).resolve().parent
    archives_dir = repo_dir / "archives"
    archives_dir.mkdir(exist_ok=True)

    if for_date is not None:
        date_str = for_date.strftime("%Y-%m-%d")
        archive_path = find_archive_for_date(archives_dir, "compromised", date_str)
        if archive_path is None:
            log.warning(
                f"No compromised archive found for {date_str} in {archives_dir}; "
                "skipping compromised-domains step for this replay."
            )
            return []
        log.info(f"Replaying compromised archive {archive_path}")
        domains = read_zip_member_text(archive_path.read_bytes()).splitlines()
        domains = [d.strip().lower() for d in domains if d.strip()]
        log.info(f"Loaded {len(domains):,} domains.")
        return domains

    log.info("Fetching known compromised domains from API")
    APICall = os.getenv('API_CALL2', '0')
    if APICall == '0':
        log.error("API_CALL2 environment variable not set")
        raise ValueError("API_CALL2 environment variable not set")
    API_KEY2 = os.getenv('URL_API_KEY2', '0')
    if API_KEY2 == '0':
        log.error("URL_API_KEY2 environment variable not set")
        raise ValueError("URL_API_KEY2 environment variable not set")
    MALWARE = os.getenv('MALWARE_STRING', '0')
    if MALWARE == '0':
        log.error("MALWARE_STRING environment variable not set")
        raise ValueError("MALWARE_STRING environment variable not set")

    latest_archive = find_latest_archive(archives_dir, "compromised")
    url = f"{APICall}{API_KEY2}{MALWARE}"
    r = fetch_url(url, secrets=[API_KEY2])
    archive_bytes = r.content
    archive_hash = hash_bytes(archive_bytes)

    if latest_archive is not None:
        latest_hash = hash_file(latest_archive)
        log.info(f"Latest local compromised archive: {latest_archive} ({latest_hash})")
        if archive_hash == latest_hash:
            # Unlike fetch_domains(), there's no expensive reclassification
            # to avoid here -- merging is a cheap no-op for domains already
            # present. Just return the known list instead of sys.exit(0):
            # that used to kill the whole process (skipping the independent
            # ad-list merge and the push for the day) for what's actually
            # a harmless, common case.
            log.info("Compromised feed has not changed since the last archive.")
            domains = read_zip_member_text(latest_archive.read_bytes()).splitlines()
            domains = [d.strip().lower() for d in domains if d.strip()]
            return domains

    now = datetime.now()
    archive_path = make_unique_timestamped_path(archives_dir, "compromised", "zip", now)
    archive_path.write_bytes(archive_bytes)
    log.info(f"Saved downloaded archive to {archive_path} (hash {archive_hash})")

    domains = read_zip_member_text(archive_bytes).splitlines()
    domains = [d.strip().lower() for d in domains if d.strip()]
    log.info(f"Fetched {len(domains):,} domains.")
    return domains


def _zip_bytes(text: str, member_name: str) -> bytes:
    """zipfile.writestr() embeds the current wall-clock time in the zip
    member's metadata by default -- harmless for reading it back, but it
    means the same text zipped twice a day apart hashes differently, which
    silently defeats fetch_ad_domains()'s "skip saving if unchanged" check
    (verified: it was creating a new archive every day regardless of
    whether the ad list had actually changed). A fixed timestamp makes the
    hash a pure function of the content, as intended."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo(member_name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, text)
    return buf.getvalue()


def fetch_ad_domains(for_date: datetime = None):
    """Fetch Peter Lowe's ad/tracking server list (see AD_LIST_URL) --
    a known/curated list, entirely outside the LLM classification scan,
    merged into both blocklists the same "no questions asked" way the
    compromised feed is (see add_ad_domains_to_blocklist).

    Archived as a zip (like the other two feeds) purely to reuse
    find_latest_archive/find_archive_for_date/read_zip_member_text as-is,
    even though the source itself is plain text, not a zip.

    Deliberately doesn't sys.exit(0) when unchanged, unlike
    fetch_domains()/fetch_compromised_domains() -- that short-circuit has
    already caused real problems (a `-d` replay silently returning [] when
    no archive existed yet for that date, and a SystemExit here would
    bypass main()'s non-fatal try/except around this call entirely, since
    SystemExit isn't an Exception subclass). Re-merging an unchanged list
    is a no-op anyway (add_known_list_to_blocklist unions into what's
    already there), so there's nothing to gain from exiting early.
    """
    repo_dir = Path(__file__).resolve().parent
    archives_dir = repo_dir / "archives"
    archives_dir.mkdir(exist_ok=True)

    if for_date is not None:
        date_str = for_date.strftime("%Y-%m-%d")
        archive_path = find_archive_for_date(archives_dir, "ads", date_str)
        if archive_path is None:
            log.warning(
                f"No ad-domains archive found for {date_str} in {archives_dir}; "
                "skipping ad-domains step for this replay."
            )
            return []
        log.info(f"Replaying ad-domains archive {archive_path}")
        domains = read_zip_member_text(archive_path.read_bytes()).splitlines()
        domains = [d.strip().lower() for d in domains if d.strip()]
        log.info(f"Loaded {len(domains):,} ad domains.")
        return domains

    log.info("Fetching known ad/tracking domains")
    r = fetch_url(AD_LIST_URL, secrets=[])
    text = r.text
    domains = [d.strip().lower() for d in text.splitlines() if d.strip() and not d.strip().startswith("#")]
    archive_bytes = _zip_bytes("\n".join(domains) + "\n", "ads.txt")
    archive_hash = hash_bytes(archive_bytes)

    latest_archive = find_latest_archive(archives_dir, "ads")
    if latest_archive is not None:
        latest_hash = hash_file(latest_archive)
        log.info(f"Latest local ad-domains archive: {latest_archive} ({latest_hash})")
        if archive_hash == latest_hash:
            log.info(f"Ad-domains list has not changed since the last archive. Using {len(domains):,} domains.")
            return domains

    now = datetime.now()
    archive_path = make_unique_timestamped_path(archives_dir, "ads", "zip", now)
    archive_path.write_bytes(archive_bytes)
    log.info(f"Saved downloaded ad-domains archive to {archive_path} (hash {archive_hash})")
    log.info(f"Fetched {len(domains):,} ad domains.")
    return domains


def add_known_list_to_blocklist(
    domains, blocklist_path: Path = None, when: datetime = None, write_log: bool = True,
    classification: str = "malware-list", reason: str = "on malware list",
    log_prefix: str = "compromised_added", log_noun: str = "compromised",
):
    """Merge a known/curated domain list (compromised feed, ad list, ...)
    into a blocklist "no questions asked" -- no LLM classification involved.

    Kept as a single read-modify-write convenience function for standalone/
    manual use; main() itself merges every known-list source into an
    in-memory set and writes each blocklist once at the end instead (see
    get_known_lists() and its use in main()), rather than once per source."""
    blocklist_path = blocklist_path or Path("blocklist.txt")
    log.info(f"Adding {log_noun} domains to {blocklist_path}")
    existing_domains = load_valid_domains(blocklist_path)

    added_entries = []
    new_domains = set()
    for domain in domains:
        cleaned = domain.strip().lower()
        if not is_valid_domain(cleaned):
            continue

        if cleaned not in existing_domains:
            added_entries.append({
                "domain": cleaned,
                "classification": classification,
                "reason": reason,
            })
        new_domains.add(cleaned)

    combined_domains = existing_domains.union(new_domains)
    total = write_blocklist(blocklist_path, combined_domains)

    if write_log:
        write_known_list_log(added_entries, when=when, prefix=log_prefix, noun=log_noun)
    return added_entries, total


def add_compromised_to_blocklist(compromised, blocklist_path: Path = None, when: datetime = None, write_log: bool = True):
    return add_known_list_to_blocklist(
        compromised, blocklist_path=blocklist_path, when=when, write_log=write_log,
        classification="malware-list", reason="on malware list",
        log_prefix="compromised_added", log_noun="compromised",
    )


def add_ad_domains_to_blocklist(ad_domains, blocklist_path: Path = None, when: datetime = None, write_log: bool = True):
    return add_known_list_to_blocklist(
        ad_domains, blocklist_path=blocklist_path, when=when, write_log=write_log,
        classification="ad-list", reason="on known ad/tracking server list",
        log_prefix="ad_domains_added", log_noun="ad",
    )


def get_known_lists():
    """Known/curated sources merged into both blocklists "no questions
    asked", entirely outside the LLM classification scan. Adding a new one
    means adding an entry here -- main()'s loop, and write_daily_digest()'s
    known_list_results parameter, don't need to change.

    A function rather than a module-level constant so it looks up
    fetch_compromised_domains/fetch_ad_domains by name each time main()
    runs, instead of baking in whatever those names pointed to at import
    time -- a module-level list literal would silently ignore a test (or a
    one-off script) that monkeypatches ng.fetch_compromised_domains, since
    the list would already hold a reference to the original function."""
    return [
        {
            "name": "compromised",
            "display_name": "Compromised Domains",
            "fetch": fetch_compromised_domains,
            "classification": "malware-list",
            "reason": "on malware list",
            "log_prefix": "compromised_added",
            "log_noun": "compromised",
        },
        {
            "name": "ads",
            "display_name": "Ad/Tracking Domains",
            "fetch": fetch_ad_domains,
            "classification": "ad-list",
            "reason": "on known ad/tracking server list",
            "log_prefix": "ad_domains_added",
            "log_noun": "ad",
        },
    ]


def parse_args():
    parser = argparse.ArgumentParser(description="NRDGuard domain blocklist pipeline")
    parser.add_argument(
        "-d", "--date",
        metavar="MMDDYYYY",
        help=(
            "Reprocess an archived feed for this date instead of fetching "
            "today's feed, e.g. -d 07132026 for 2026-07-13. Reads "
            "archives/domains_<date>.zip (and compromised_<date>.zip if "
            "present) instead of hitting the network."
        ),
    )
    parser.add_argument(
        "--resume", action="store_true",
        help=(
            "With -d, skip re-classification if a flagged_domains_<date> and "
            "classification_stats_<date> log already exist for that date, "
            "and resume from the known-list-merge step onward instead. Use "
            "this to finish a run that died partway through (e.g. a network "
            "blip during the compromised-feed fetch) without re-running the "
            "expensive classification phase. Fails if no prior classification "
            "exists for that date -- omit --resume to run one."
        ),
    )
    return parser.parse_args()


def main():
    global RUN_START
    RUN_START = time.time()
    load_local_env()

    args = parse_args()
    target_date = None
    if args.date:
        try:
            target_date = datetime.strptime(args.date, "%m%d%Y")
        except ValueError:
            log.error(f"Invalid --date value {args.date!r}; expected MMDDYYYY (e.g. 07132026)")
            sys.exit(1)

    if args.resume and target_date is None:
        log.error("--resume requires -d/--date (there's nothing to resume for a live run).")
        sys.exit(1)

    models = get_configured_models()

    if target_date is not None:
        log.info(f"=== Unsafe New URL starting (replaying {target_date:%Y-%m-%d}) === models={models}")
    else:
        log.info(f"=== Unsafe New URL starting === models={models}")

    resume_state = None
    if args.resume:
        resume_state = load_resume_state(target_date)
        if resume_state is None:
            log.error(
                f"--resume given but no prior classification found for {target_date:%Y-%m-%d} "
                "(need both a flagged_domains and a classification_stats log for that date "
                "in logs/json/ -- the latter is only written by runs after this feature was "
                "added, so an older date can't be resumed this way). Omit --resume to run a "
                "full classification for this date."
            )
            sys.exit(1)
        log.info(f"--resume: found existing classification for {target_date:%Y-%m-%d}; skipping re-classification.")

    # A previous run's push can fail (VPN kill switch blocking traffic while
    # it reconnects, most commonly) after its commit already succeeded --
    # that commit is then stuck local-only until something pushes it. Flush
    # any such pending commit before starting today's work. CREATED_FILES is
    # still empty here, so this can only push what a prior run already
    # committed -- it commits nothing new of its own.
    try:
        repo_dir = Path(__file__).resolve().parent
        branch = os.getenv("GITHUB_BRANCH", "main")
        pending = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-list", "--count", f"origin/{branch}..HEAD"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        pending_count = int(pending.stdout.strip()) if pending.returncode == 0 and pending.stdout.strip().isdigit() else 0
        if pending_count:
            log.info(f"Found {pending_count} commit(s) not yet on GitHub from a previous run; attempting to push before starting today's work.")
            if push_to_github():
                log.info("Pending commit(s) pushed successfully.")
    except Exception:
        log.warning("Catch-up push for a previous run's pending commit failed; continuing with today's run.", exc_info=True)

    try:
        get_api_key()
        domains = fetch_domains(target_date)
        classification_skipped = False

        if resume_state is not None:
            all_flagged = resume_state["all_flagged"]
            for p in resume_state["paths"]:
                register_created(p)
            model_names_seen = list(resume_state["per_model_stats"].keys())
            per_model = {
                m: {
                    "flagged": [e for e in all_flagged if e.get("model") == m],
                    "stats": resume_state["per_model_stats"][m],
                }
                for m in model_names_seen
            }
            votes = {}
            for entry in all_flagged:
                votes.setdefault(entry["domain"], {}).setdefault(entry["category"], set()).add(entry["model"])
            consensus_flagged = []
            required = set(model_names_seen)
            for domain, category_votes in votes.items():
                for category, models_seen in category_votes.items():
                    if models_seen >= required:
                        consensus_flagged.append({"domain": domain, "category": category, "models": sorted(models_seen)})
        elif domains is None:
            # Feed unchanged since the last run -- reclassifying it would
            # waste ~2 hours for the same result, so skip that, but still
            # run the independent known-list merges and push below (see
            # fetch_domains()'s docstring for why this used to sys.exit(0)
            # and skip those too).
            classification_skipped = True
            log.info("Domains feed unchanged since the last run; skipping classification, but still checking known-list feeds and pushing.")
            per_model = {
                m: {"flagged": [], "stats": {"total_batches": 0, "zero_flag_batches": 0, "failed_batches": 0, "category_counts": Counter()}}
                for m in models
            }
            all_flagged = []
            consensus_flagged = []
            write_daily_log(all_flagged, when=target_date)
            write_category_summary(all_flagged, when=target_date)
        else:
            per_model, all_flagged, consensus_flagged = classify_domains_multi(domains, models)

            nameservers = resolve_nameservers({entry["domain"] for entry in all_flagged})
            for entry in all_flagged:
                entry["nameserver"] = nameservers.get(entry["domain"], "")

            write_daily_log(all_flagged, when=target_date)
            write_category_summary(all_flagged, when=target_date)
            write_classification_stats(per_model, when=target_date)

        list1_path = Path("blocklist.txt")
        list2_path = Path("blocklist_consensus.txt")

        # Read each blocklist once, merge everything (classification +
        # every known-list source) into an in-memory set, write once at the
        # end -- rather than a full read+rewrite of a multi-million-line
        # file per source, which is what repeatedly calling
        # add_to_blocklist()/add_known_list_to_blocklist() would do.
        list1_domains = load_valid_domains(list1_path)
        list2_domains = load_valid_domains(list2_path)

        for entry in all_flagged:
            if is_valid_domain(entry["domain"]):
                list1_domains.add(entry["domain"])
        for entry in consensus_flagged:
            if is_valid_domain(entry["domain"]):
                list2_domains.add(entry["domain"])

        list1_total_after_classify = len(list1_domains)
        list2_total_after_classify = len(list2_domains)

        # A flaky known-list fetch shouldn't take down a run that already
        # completed the expensive part (classification) -- same reasoning
        # as skipping a single failed classification batch rather than
        # aborting the whole thing. domains-monitor.com has dropped the
        # compromised-feed call specifically, well past fetch_url()'s retry
        # window, repeatedly; losing/delaying an entire day's classification
        # over it is worse than shipping a run with that one source visibly
        # flagged as skipped in the digest.
        known_list_results = {}
        for source in get_known_lists():
            fetched_domains = []
            failed = False
            try:
                fetched_domains = source["fetch"](target_date)
            except Exception as e:
                failed = True
                log.error(f"{source['display_name']} fetch failed, skipping that step for this run: {e}", exc_info=True)

            added_entries = []
            for domain in fetched_domains:
                cleaned = domain.strip().lower()
                if not is_valid_domain(cleaned):
                    continue
                if cleaned not in list1_domains:
                    added_entries.append({"domain": cleaned, "classification": source["classification"], "reason": source["reason"]})
                list1_domains.add(cleaned)
                list2_domains.add(cleaned)

            if not failed:
                write_known_list_log(added_entries, when=target_date, prefix=source["log_prefix"], noun=source["log_noun"])

            known_list_results[source["name"]] = {
                "display_name": source["display_name"],
                "fetched": len(fetched_domains),
                "added": added_entries,
                "failed": failed,
            }

        list1_final_total = write_blocklist(list1_path, list1_domains)
        list2_final_total = write_blocklist(list2_path, list2_domains)

        write_daily_digest(
            total_domains_scanned=len(domains) if domains else 0,
            per_model=per_model,
            all_flagged=all_flagged,
            consensus_flagged=consensus_flagged,
            list1_total_after_classification=list1_total_after_classify,
            list2_total_after_classification=list2_total_after_classify,
            list1_final_total=list1_final_total,
            list2_final_total=list2_final_total,
            known_list_results=known_list_results,
            when=target_date,
            classification_skipped=classification_skipped,
        )
        hash_blocklist()
        push_to_github()
        log.info("=== Pipeline complete ===")
    except Exception as e:
        log.error(f"Unsafe New URL failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
