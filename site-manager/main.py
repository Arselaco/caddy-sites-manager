from __future__ import annotations

import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

import requests
import yaml
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="[%(asctime)s] %(levelname)s %(message)s",
)

LOGGER = logging.getLogger("site-manager")

DOMAINS_FILE = Path(os.getenv("DOMAINS_FILE", "/work/domains.yaml"))
GENERATED_DIR = Path(os.getenv("GENERATED_DIR", "/work/generated"))
BASE_FILE = Path(os.getenv("CADDY_BASE_FILE", "/work/base/Caddyfile"))
CADDY_ADMIN_URL = os.getenv("CADDY_ADMIN_URL", "http://caddy:2019").rstrip("/")
DEBOUNCE_SECONDS = float(os.getenv("SYNC_DEBOUNCE_SECONDS", "2.0"))
RETRY_SECONDS = float(os.getenv("SYNC_RETRY_SECONDS", "30.0"))
SYNC_LOCK = threading.Lock()


def expand_env(value: str) -> str:
    """Expand shell-style environment variables in the provided string."""
    return os.path.expandvars(value)


def ensure_paths() -> None:
    if not DOMAINS_FILE.exists():
        raise FileNotFoundError(f"Domain inventory file not found: {DOMAINS_FILE}")
    if not BASE_FILE.exists():
        raise FileNotFoundError(f"Base Caddyfile not found: {BASE_FILE}")
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)


def sanitize_filename(seed: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9-_]+", "_", seed)
    safe = safe.strip("._") or "site"
    return f"{safe}.caddy"


def normalize_entry(raw: Dict[str, Any], index: int) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"Entry at index {index} must be a mapping")

    if "domain" not in raw:
        raise ValueError(f"Entry at index {index} is missing required key 'domain'")

    primary = expand_env(str(raw["domain"]).strip())
    if not primary:
        raise ValueError(f"Entry at index {index} has empty domain value")

    aliases: Iterable[str] = raw.get("aliases", [])
    if isinstance(aliases, str):
        aliases = [aliases]

    all_hosts: List[str] = [primary]
    for alias in aliases:
        expanded = expand_env(str(alias).strip())
        if expanded and expanded not in all_hosts:
            all_hosts.append(expanded)

    upstream_cfg = raw.get("upstream")
    if upstream_cfg is None:
        raise ValueError(f"Entry '{primary}' is missing 'upstream' definition")

    upstream_url: str
    if isinstance(upstream_cfg, str):
        upstream_url = expand_env(upstream_cfg).strip()
        if not upstream_url:
            raise ValueError(f"Entry '{primary}' upstream string is empty")
        if "://" not in upstream_url:
            upstream_url = f"http://{upstream_url}"
    elif isinstance(upstream_cfg, dict):
        scheme = expand_env(str(upstream_cfg.get("scheme", "http"))).strip() or "http"
        host = upstream_cfg.get("host")
        port = upstream_cfg.get("port")
        if host is None or port is None:
            raise ValueError(
                f"Entry '{primary}' upstream mapping requires both 'host' and 'port'"
            )
        host = expand_env(str(host).strip())
        port = expand_env(str(port)).strip()
        if not host or not port:
            raise ValueError(f"Entry '{primary}' upstream host/port cannot be empty")
        upstream_url = f"{scheme}://{host}:{port}"
    else:
        raise ValueError(
            f"Entry '{primary}' upstream must be string or mapping, got {type(upstream_cfg)}"
        )

    preserve_host = bool(raw.get("preserve_host", True))
    timeouts = raw.get("timeouts") or {}
    health_cfg = raw.get("healthcheck") or {}

    entry: Dict[str, Any] = {
        "name": primary,
        "hosts": all_hosts,
        "upstream": upstream_url,
        "preserve_host": preserve_host,
        "timeouts": {
            key: expand_env(str(value))
            for key, value in timeouts.items()
            if value is not None
        },
        "healthcheck": {
            key: expand_env(str(value))
            for key, value in health_cfg.items()
            if value is not None
        },
    }

    return entry


def load_inventory() -> List[Dict[str, Any]]:
    with DOMAINS_FILE.open("r", encoding="utf-8") as fp:
        loaded = yaml.safe_load(fp) or []

    if isinstance(loaded, dict):
        items = loaded.get("sites") or []
    elif isinstance(loaded, list):
        items = loaded
    else:
        raise ValueError("domains.yaml must contain a list or a 'sites' mapping")

    normalized = []
    for idx, raw in enumerate(items):
        normalized.append(normalize_entry(raw, idx))
    return normalized


def render_entry(entry: Dict[str, Any]) -> str:
    hosts_line = ", ".join(entry["hosts"])
    lines = [f"{hosts_line} {{"]
    lines.append("    encode gzip zstd")
    lines.append("")
    
    # Proxy all requests to upstream
    timeouts = entry.get("timeouts", {})
    health = entry.get("healthcheck", {})

    reverse_line = f"    reverse_proxy {entry['upstream']}"
    block_lines: List[str] = []

    requires_block = bool(health or timeouts or entry.get("preserve_host", True))

    if requires_block:
        block_lines.append(reverse_line + " {")
        if health:
            uri = health.get("path") or health.get("uri")
            interval = health.get("interval")
            timeout = health.get("timeout")
            if uri:
                block_lines.append(f"        health_uri {uri}")
            if interval:
                block_lines.append(f"        health_interval {interval}")
            if timeout:
                block_lines.append(f"        health_timeout {timeout}")
        if timeouts:
            if timeout := timeouts.get("dial"):
                block_lines.append(f"        dial_timeout {timeout}")
            if timeout := timeouts.get("read"):
                block_lines.append(f"        read_timeout {timeout}")
            if timeout := timeouts.get("write"):
                block_lines.append(f"        write_timeout {timeout}")
        if entry.get("preserve_host", True):
            block_lines.append("        header_up Host {http.request.header.Host}")
        block_lines.append("    }")
    else:
        block_lines.append(reverse_line)

    lines.extend(block_lines)
    lines.append("}")
    lines.append("")
    
    return "\n".join(lines)
    
    # Add HTTP site with explicit redirect (except for ACME challenges)
    lines.append(f"http://{hosts_line} {{")
    lines.append(f"    redir https://{entry['hosts'][0]}{{uri}} permanent")
    lines.append("}")
    lines.append("")
    
    return "\n".join(lines)


def write_entries(entries: List[Dict[str, Any]]) -> bool:
    desired_files = {}
    changed = False

    for entry in entries:
        filename = sanitize_filename(entry["name"])
        desired_files[filename] = entry
        target_path = GENERATED_DIR / filename
        content = render_entry(entry)

        if target_path.exists():
            try:
                current = target_path.read_text(encoding="utf-8")
            except OSError as exc:
                LOGGER.warning("Failed to read %s: %s", target_path, exc)
                current = None
            if current == content:
                continue

        tmp_path = target_path.with_suffix(".tmp")
        tmp_path.write_text(content, encoding="utf-8")
        tmp_path.replace(target_path)
        LOGGER.info("Updated site definition %s", target_path.name)
        changed = True

    for existing in GENERATED_DIR.glob("*.caddy"):
        if existing.name not in desired_files:
            existing.unlink()
            LOGGER.info("Removed stale definition %s", existing.name)
            changed = True

    return changed


def reload_caddy() -> None:
    """Reload Caddy configuration by posting the raw Caddyfile content."""
    config_text = BASE_FILE.read_text(encoding="utf-8")
    url = f"{CADDY_ADMIN_URL}/load"
    LOGGER.debug("Reloading Caddy via %s", url)
    
    # Send the raw Caddyfile content with proper content-type
    headers = {"Content-Type": "text/caddyfile"}
    response = requests.post(url, data=config_text, headers=headers, timeout=15)
    
    if response.status_code >= 400:
        raise RuntimeError(f"Caddy reload failed: {response.status_code} {response.text}")
    LOGGER.info("Caddy configuration reloaded")


def sync_once() -> None:
    if not SYNC_LOCK.acquire(blocking=False):
        LOGGER.debug("Sync already in progress; skipping request")
        return

    attempts = 0
    try:
        while True:
            attempts += 1
            try:
                entries = load_inventory()
                changed = write_entries(entries)
                if changed:
                    reload_caddy()
                else:
                    LOGGER.debug("No changes detected; skipping reload")
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.error("Sync attempt %s failed: %s", attempts, exc)
                LOGGER.debug("Full stack", exc_info=exc)
                LOGGER.info("Retrying in %s seconds", RETRY_SECONDS)
                time.sleep(RETRY_SECONDS)
    finally:
        SYNC_LOCK.release()


class DebouncedHandler(FileSystemEventHandler):
    def __init__(self, target: Path, callback):
        super().__init__()
        self._target = target.resolve()
        self._callback = callback
        self._timer: threading.Timer | None = None

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        event_path = Path(event.src_path).resolve()
        if event_path != self._target and getattr(event, "dest_path", None):
            dest = Path(getattr(event, "dest_path")).resolve()
            if dest != self._target:
                return
        elif event_path != self._target:
            return

        LOGGER.debug("Change detected for %s", self._target)
        self._debounce()

    def _debounce(self) -> None:
        if self._timer:
            self._timer.cancel()
        self._timer = threading.Timer(DEBOUNCE_SECONDS, self._callback)
        self._timer.daemon = True
        self._timer.start()


def start_watchdog(callback) -> Observer:
    observer = Observer()
    handler = DebouncedHandler(DOMAINS_FILE, callback)
    observer.schedule(handler, DOMAINS_FILE.parent.as_posix(), recursive=False)
    observer.start()
    LOGGER.info("Watching %s for changes", DOMAINS_FILE)
    return observer


def main() -> None:
    ensure_paths()
    sync_once()

    observer = start_watchdog(sync_once)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        LOGGER.info("Stopping site manager")
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
