import io
import json
import os
import logging
import re
import sys
import zipfile
import csv
import hashlib
import shutil
import subprocess
import collections.abc
from datetime import datetime
from pathlib import Path
import requests
import time

try:
    import ollama
    ollama_chat = ollama.chat
except Exception:
    ollama_chat = None

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger(__name__)

# Global env variables
BATCH_SIZE = 500

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


def generate_with_llama(prompt: str, max_tokens: int = 1000, system_prompt: str = None) -> str:
    """Generate text using the local Ollama chat API."""
    load_local_env()

    model_name = os.getenv("LLAMA_MODEL_NAME", "gemma4:12b")
    if ollama_chat is not None:
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            response = ollama_chat(model=model_name, messages=messages, think=False, stream=False, options={"num_predict": 200})
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
        except Exception as e:
            raise RuntimeError(
                f"Ollama chat failed: {e}. Install and run the Ollama service locally and ensure the model '{model_name}' is available."
            )

    raise RuntimeError(
        "No Ollama chat client is available. Install the ollama package and ensure the local Ollama service is running."
    )


def classify_batch(batch):
    system_prompt = """You are a domain name threat classifier. You analyze lists of newly registered domains and flag any that appear in these categories:
- Scams/Phishing (e.g. paypa1-secure.com, amazon-login-verify.net)
- Typosquatting of well-known brands (e.g. gooogle.com, arnazon.com)
- Gambling sites (e.g. online-casino.net, bet365-login.com)
- Malware distribution or potential C2 (e.g. malware-download.com, c2-server.net)
- Ads (e.g. adsrvs.com, adclicks.net)
- Tracking or analytics (e.g. trackingpixel.com, analytics-service.net)
- Cryptojacking (e.g. cryptomining.com, coin-hive.com)
- AI Deepfake or impersonation (e.g. deepfake-celebrity.com, fake-ai-avatar.net)

Return ONLY the flagged domains, one per line, in csv format. DOMAIN, CATEGORY. (e.g. paypals.com, Scams/Phishing)
If the domain is not suspicious or does not have a confidence score of 0.9 or higher, do not return the domain."""

    user_input = chr(10).join(batch)
    resp_text = generate_with_llama(user_input, max_tokens=1000, system_prompt=system_prompt)
    flagged = resp_text.strip().splitlines()
    return [d.strip().lower() for d in flagged if d.strip()]


def classify_domains(domains):
    all_flagged = []
    total_batches = (len(domains) + BATCH_SIZE - 1) // BATCH_SIZE

    for i in range(0, len(domains), BATCH_SIZE):
        batch = domains[i:i + BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        flagged = classify_batch(batch)
        all_flagged.extend(flagged)
        log.info(f"Batch {batch_num}/{total_batches}: {len(flagged)} flagged")

    log.info(f"Total flagged: {len(all_flagged):,}")
    return all_flagged


def write_daily_log(flagged):
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    now = datetime.now()

    csv_path = make_unique_timestamped_path(log_dir, "flagged_domains", "csv", now)
    json_path = make_unique_timestamped_path(log_dir, "flagged_domains", "json", now)

    parsed_entries = []
    for entry in flagged:
        parts = [p.strip() for p in entry.split(",")]
        if len(parts) >= 2:
            domain, classification = parts[0], parts[1]
        else:
            domain, classification = entry, "unknown"
        parsed_entries.append({
            "domain": domain,
            "classification": classification,
        })

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["domain", "classification"])
        writer.writeheader()
        writer.writerows(parsed_entries)

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(parsed_entries, handle, indent=2)
        handle.write("\n")

    register_created(csv_path)
    register_created(json_path)
    log.info(f"Saved {len(flagged)} flagged entries to {csv_path} and {json_path}")
    return csv_path, json_path


def write_compromised_log(entries):
    if not entries:
        log.info("No new compromised domains to log")
        return None

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    now = datetime.now()

    csv_path = make_unique_timestamped_path(log_dir, "compromised_added", "csv", now)
    json_path = make_unique_timestamped_path(log_dir, "compromised_added", "json", now)

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["domain", "classification", "reason"])
        writer.writeheader()
        writer.writerows(entries)

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(entries, handle, indent=2)
        handle.write("\n")
    register_created(csv_path)
    register_created(json_path)
    log.info(f"Saved {len(entries)} newly added compromised domains to {csv_path} and {json_path}")
    return csv_path, json_path


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


def find_latest_archive(archives_dir: Path, prefix: str):
    candidates = sorted(
        [path for path in archives_dir.glob(f"{prefix}_*.zip") if path.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


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

    # try to enable Git LFS and track the blocklist to avoid pushing >25MB files
    try:
        subprocess.run(["git", "-C", str(repo_dir), "lfs", "install"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["git", "-C", str(repo_dir), "lfs", "track", "blocklist.txt"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        log.warning("git lfs setup failed or not available: %s", exc)

    token = os.getenv("GITHUB_TOKEN")
    repo_url = os.getenv("GITHUB_REPO")
    branch = os.getenv("GITHUB_BRANCH", "UnsafeNewURL")

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

    # Always include blocklist.txt and its hash if present (primary artifact)
    try:
        if blocklist_path.exists() and blocklist_path.resolve() not in files_to_add:
            files_to_add.insert(0, blocklist_path)
        blocklist_sha = repo_dir / (blocklist_path.name + ".sha256")
        if blocklist_sha.exists() and blocklist_sha.resolve() not in files_to_add:
            files_to_add.insert(1, blocklist_sha)
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

    remote_url = f"https://x-access-token:{token}@github.com/{repo_url}.git"
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

    try:
        subprocess.run(["git", "-C", str(repo_dir), "push", "-u", "origin", branch], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        log.warning("Git push failed: %s", exc)
        log.warning("Skipping GitHub push and continuing without failing the entire pipeline.")
        return None

    log.info("Pushed blocklist, logs, and hashes to GitHub")
    return True


def get_api_key():
    log.info("Fetching API Key for URL API")
    URL_API_KEY = os.getenv('URL_API_KEY', '0')
    if URL_API_KEY == '0':
        log.error("URL_API_KEY environment variable not set")
        raise ValueError("URL_API_KEY environment variable not set")


def fetch_domains():
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

    repo_dir = Path(__file__).resolve().parent
    archives_dir = repo_dir / "archives"
    archives_dir.mkdir(exist_ok=True)

    latest_archive = find_latest_archive(archives_dir, "domains")
    url = f"{APICall}{URL_API_KEY}{DAILY_UPDATE}"
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    archive_bytes = r.content
    archive_hash = hash_bytes(archive_bytes)

    if latest_archive is not None:
        latest_hash = hash_file(latest_archive)
        log.info(f"Latest local domains archive: {latest_archive} ({latest_hash})")
        if archive_hash == latest_hash:
            log.info("Domains feed has not changed since the last archive. Exiting.")
            sys.exit(0)

    now = datetime.now()
    archive_path = make_unique_timestamped_path(archives_dir, "domains", "zip", now)
    archive_path.write_bytes(archive_bytes)
    log.info(f"Saved downloaded archive to {archive_path} (hash {archive_hash})")

    z = zipfile.ZipFile(io.BytesIO(archive_bytes))
    domains = z.read(z.namelist()[0]).decode().splitlines()
    domains = [d.strip().lower() for d in domains if d.strip()]
    log.info(f"Fetched {len(domains):,} domains.")
    return domains


def add_to_blocklist(flagged):
    log.info("Adding flagged domains to blocklist")
    blocklist_path = Path("blocklist.txt")
    existing_domains = set()
    if blocklist_path.exists():
        with blocklist_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                cleaned = line.strip().lower()
                if is_valid_domain(cleaned):
                    existing_domains.add(cleaned)

    new_domains = set()
    for entry in flagged:
        if not entry:
            continue
        domain = entry.split(",")[0].strip().lower()
        if is_valid_domain(domain):
            new_domains.add(domain)

    combined_domains = existing_domains.union(new_domains)

    with blocklist_path.open("w", encoding="utf-8") as handle:
        for domain in sorted(combined_domains):
            handle.write(f"{domain}\n")

    register_created(blocklist_path)
    log.info(f"Blocklist updated. Total domains: {len(combined_domains):,}")


def fetch_compromised_domains():
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

    repo_dir = Path(__file__).resolve().parent
    archives_dir = repo_dir / "archives"
    archives_dir.mkdir(exist_ok=True)

    latest_archive = find_latest_archive(archives_dir, "compromised")
    url = f"{APICall}{API_KEY2}{MALWARE}"
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    archive_bytes = r.content
    archive_hash = hash_bytes(archive_bytes)

    if latest_archive is not None:
        latest_hash = hash_file(latest_archive)
        log.info(f"Latest local compromised archive: {latest_archive} ({latest_hash})")
        if archive_hash == latest_hash:
            log.info("Compromised feed has not changed since the last archive. Exiting.")
            sys.exit(0)

    now = datetime.now()
    archive_path = make_unique_timestamped_path(archives_dir, "compromised", "zip", now)
    archive_path.write_bytes(archive_bytes)
    log.info(f"Saved downloaded archive to {archive_path} (hash {archive_hash})")

    z = zipfile.ZipFile(io.BytesIO(archive_bytes))
    domains = z.read(z.namelist()[0]).decode().splitlines()
    domains = [d.strip().lower() for d in domains if d.strip()]
    log.info(f"Fetched {len(domains):,} domains.")
    return domains


def add_compromised_to_blocklist(compromised):
    log.info("Adding compromised domains to blocklist")
    blocklist_path = Path("blocklist.txt")
    existing_domains = set()
    if blocklist_path.exists():
        with blocklist_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                cleaned = line.strip().lower()
                if is_valid_domain(cleaned):
                    existing_domains.add(cleaned)

    added_entries = []
    new_domains = set()
    for domain in compromised:
        cleaned = domain.strip().lower()
        if not is_valid_domain(cleaned):
            continue

        if cleaned not in existing_domains:
            added_entries.append({
                "domain": cleaned,
                "classification": "malware-list",
                "reason": "on malware list",
            })
        new_domains.add(cleaned)

    combined_domains = existing_domains.union(new_domains)

    with blocklist_path.open("w", encoding="utf-8") as handle:
        for domain in sorted(combined_domains):
            handle.write(f"{domain}\n")

    register_created(blocklist_path)
    log.info(f"Blocklist updated with compromised domains. Total domains: {len(combined_domains):,}")

    write_compromised_log(added_entries)
    return added_entries


def main():
    global RUN_START
    RUN_START = time.time()
    log.info("=== Unsafe New URL starting ===")
    try:
        get_api_key()
        domains = fetch_domains()
        flagged = classify_domains(domains)
        write_daily_log(flagged)
        add_to_blocklist(flagged)
        compromised = fetch_compromised_domains()
        add_compromised_to_blocklist(compromised)
        hash_blocklist()
        push_to_github()
        log.info("=== Pipeline complete ===")
    except Exception as e:
        log.error(f"Unsafe New URL failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
