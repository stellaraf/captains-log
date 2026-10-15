"""Poll the configured GitHub stable release and apply verified appliance bundles.

GitHub is distribution, not publisher-key enrollment. No release can select a
command, hook, URL origin, key, filesystem path or unsigned installation mode.
"""
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import tempfile
import time
from urllib.parse import urlsplit

from .common import Refused, atomic_json, audit, locked, require_linux_root, run, trusted_file
from .update_enrollment import enrolled_key, _read, _tree
from .updates import UpdateManager, _unique, verify_release

CONFIG = Path("/etc/nebulalog/github-updates.json")
PUBLIC_KEY = Path("/etc/nebulalog/release-public.pem")
POLL_SECONDS = 900
MAX_RELEASE = 1024 * 1024
MAX_BUNDLE = 16 * 1024**3
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
CDN_HOSTS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
STATES = {"disabled", "checking", "no_release", "up_to_date", "downloading", "installing", "installed", "blocked", "failed"}


class HTTPFailure(Refused):
    def __init__(self, status):
        self.status = status
        super().__init__("GitHub release request failed")


class GitHubTransport:
    def __init__(self, token=None, *, context=None, connection_factory=http.client.HTTPSConnection):
        self.token = token
        self.context = context or ssl.create_default_context()
        self.connection_factory = connection_factory

    def fetch(self, path, *, maximum, output=None, expected_size=None, expected_hash=None):
        if not re.fullmatch(r"/repos/[A-Za-z0-9._/-]+", path):
            raise Refused("Unexpected GitHub API path")
        url = "https://api.github.com" + path
        deadline = time.monotonic() + 600
        for redirect in range(4):
            location = urlsplit(url)
            host = location.hostname
            if (location.scheme != "https" or location.username or location.password or location.fragment
                    or location.port not in (None, 443) or host not in {"api.github.com", *CDN_HOSTS}):
                raise Refused("GitHub asset redirect left the approved HTTPS origins")
            # Authorization goes only to the original GitHub API, never a CDN.
            headers = {"User-Agent": "Captains-Log-Updater", "Accept-Encoding": "identity",
                       "Accept": "application/octet-stream" if "/releases/assets/" in path else "application/vnd.github+json"}
            if host == "api.github.com":
                if redirect:
                    raise Refused("Unexpected redirect back to the GitHub API")
                headers["X-GitHub-Api-Version"] = "2026-03-10"
                if self.token:
                    headers["Authorization"] = "Bearer " + self.token
            connection = self.connection_factory(host, 443, context=self.context, timeout=30)
            try:
                connection.request("GET", location.path + ("?" + location.query if location.query else ""), headers=headers)
                response = connection.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    if "/releases/assets/" not in path:
                        raise Refused("Repository redirects require explicit reconfiguration")
                    url = response.getheader("Location", "")
                    continue
                if response.status != 200:
                    raise HTTPFailure(response.status)
                if response.getheader("Content-Encoding", "identity") != "identity":
                    raise Refused("Unexpected encoded release response")
                length = response.getheader("Content-Length")
                if length is not None and (not length.isdecimal() or int(length) > maximum
                        or expected_size is not None and int(length) != expected_size):
                    raise Refused("Release response length is outside its declared bounds")
                size, digest, chunks = 0, hashlib.sha256(), []
                while True:
                    if time.monotonic() > deadline:
                        raise Refused("Release transfer exceeded its deadline")
                    part = response.read(min(65536, maximum - size + 1))
                    if not part:
                        break
                    size += len(part)
                    if size > maximum:
                        raise Refused("Release response exceeds its size limit")
                    digest.update(part)
                    if output is None:
                        chunks.append(part)
                    else:
                        output.write(part)
                if length is not None and size != int(length) or expected_size is not None and size != expected_size:
                    raise Refused("Incomplete release transfer")
                if expected_hash is not None and digest.hexdigest() != expected_hash:
                    raise Refused("Downloaded artifact hash mismatch")
                return b"".join(chunks) if output is None else {"bytes": size, "sha256": digest.hexdigest()}
            finally:
                connection.close()
        raise Refused("Too many release asset redirects")


def load_policy(path=CONFIG):
    value = json.loads(_read(path, 16384), object_pairs_hook=_unique)
    if (not isinstance(value, dict) or set(value) - {"schema", "repository", "automatic_updates", "automatic_livepatch", "poll_interval_seconds", "token_file"}
            or type(value.get("schema")) is not int or value["schema"] != 1 or not isinstance(value.get("repository"), str)
            or not REPOSITORY.fullmatch(value["repository"]) or value["repository"].endswith(".git")
            or type(value.get("automatic_updates")) is not bool or type(value.get("poll_interval_seconds")) is not int
            or value["poll_interval_seconds"] != POLL_SECONDS
            or type(value.get("automatic_livepatch", False)) is not bool):
        raise Refused("Invalid GitHub update policy")
    token = None
    if value.get("token_file") is not None:
        path = Path(value["token_file"])
        if path != Path("/var/lib/nebulalog/configuration/github-read-token"):
            raise Refused("GitHub credentials require the fixed encrypted configuration path")
        trusted_file(path)
        if path.stat().st_mode & 0o077:
            raise Refused("GitHub read token must be root-only")
        token = _read(path, 4096).decode().strip()
        if not re.fullmatch(r"[A-Za-z0-9_]{20,255}", token):
            raise Refused("Invalid GitHub read token")
    return value, token


class GitHubUpdater:
    def __init__(self, manager=None, *, transport=None, public_key=PUBLIC_KEY, runner=run,
                 clock=lambda: datetime.now(timezone.utc)):
        self.manager = manager or UpdateManager()
        self.transport, self.public_key, self.runner, self.clock = transport, public_key, runner, clock
        self.state = self.manager.state

    def record(self, policy, status, **details):
        if status not in STATES:
            raise Refused("Unknown update observation")
        now = self.clock()
        next_check = datetime.fromtimestamp((int(now.timestamp()) // POLL_SECONDS + 1) * POLL_SECONDS, timezone.utc)
        value = {"schema": 1, "repository": policy["repository"], "automatic_updates": policy["automatic_updates"],
                 "poll_interval_seconds": POLL_SECONDS, "status": status, "checked_at": now.isoformat(),
                 "next_check_at": next_check.isoformat(), **details}
        atomic_json(self.state / "github-status.json", value)
        audit(self.state / "history.jsonl", "update.github_" + status, **{k: v for k, v in details.items() if k in {"sequence", "release_id", "error_type", "http_status"}})
        return value

    def poll(self, policy):
        require_linux_root()
        _tree(self.state)
        with locked(self.state / "github-poll.lock"):
            if not policy["automatic_updates"]:
                return self.record(policy, "disabled")
            self.record(policy, "checking")
            stage = None
            try:
                prefix = "/repos/" + policy["repository"]
                try:
                    raw = self.transport.fetch(prefix + "/releases/latest", maximum=MAX_RELEASE)
                except HTTPFailure as exc:
                    if exc.status == 404:
                        return self.record(policy, "no_release", http_status=404)
                    raise
                release = json.loads(raw, object_pairs_hook=_unique)
                if (not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False
                        or type(release.get("id")) is not int or release["id"] <= 0
                        or not isinstance(release.get("tag_name"), str)
                        or not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+", release["tag_name"])):
                    raise Refused("Only published stable versioned GitHub releases are eligible")
                assets = release.get("assets")
                if not isinstance(assets, list) or len(assets) > 100:
                    raise Refused("Invalid GitHub release assets")
                index = {}
                for asset in assets:
                    if (not isinstance(asset, dict) or not isinstance(asset.get("name"), str) or asset["name"] in index
                            or type(asset.get("id")) is not int or asset["id"] <= 0 or asset.get("state") != "uploaded"
                            or type(asset.get("size")) is not int or asset["size"] <= 0):
                        raise Refused("Ambiguous or incomplete GitHub asset metadata")
                    index[asset["name"]] = asset
                if not {"manifest.json", "manifest.sig"} <= index.keys():
                    raise Refused("Release has no appliance update manifest and signature")
                enrolled_key(self.state, self.public_key)
                manager_status = self.manager.status()
                transaction = manager_status.get("transaction") or {}
                os_transaction = manager_status.get("os_transaction") or {}
                if (manager_status.get("maintenance_release_pending") or
                        transaction.get("state", "committed") not in {"committed", "rolled_back", "preflight_failed"} or
                        os_transaction and (os_transaction.get("state") not in {"complete", "failed", "reboot_aborted"} or
                                            os_transaction.get("finalization", "complete") != "complete")):
                    return self.record(policy, "blocked", reason="recovery_pending")
                current = manager_status["current"]
                downloads = self.state / "downloads"
                downloads.mkdir(mode=0o700, exist_ok=True)
                _tree(downloads)
                stage = Path(tempfile.mkdtemp(prefix="github-", dir=downloads))
                def download(name, limit, digest=None):
                    asset = index[name]
                    if asset["size"] > limit:
                        raise Refused("GitHub asset exceeds its expected size")
                    fd = os.open(stage / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        self.transport.fetch(prefix + "/releases/assets/" + str(asset["id"]), maximum=limit, output=stream,
                                             expected_size=asset["size"], expected_hash=digest)
                        stream.flush()
                        os.fsync(stream.fileno())
                download("manifest.json", 1024 * 1024)
                download("manifest.sig", 16384)
                metadata = verify_release(stage / "manifest.json", stage / "manifest.sig", self.public_key, stage,
                                          current_sequence=-1, runner=self.runner, now=self.clock(), metadata_only=True)
                if metadata["version"] != release["tag_name"].removeprefix("v"):
                    raise Refused("Signed appliance version differs from the GitHub release tag")
                if metadata["sequence"] <= current["sequence"]:
                    if metadata["sequence"] < current["sequence"]:
                        return self.record(policy, "blocked", reason="older_release", sequence=current["sequence"])
                    if transaction.get("state") == "rolled_back":
                        return self.record(policy, "blocked", reason="release_rolled_back", sequence=current["sequence"])
                    if metadata["version"] != current.get("version"):
                        return self.record(policy, "blocked", reason="sequence_conflict", sequence=current["sequence"])
                    return self.record(policy, "up_to_date", release_id=release["id"], sequence=current["sequence"])
                # Supported paths and complete metadata are checked before downloading OCI data.
                verify_release(stage / "manifest.json", stage / "manifest.sig", self.public_key, stage,
                               current_sequence=current["sequence"], current_versions={k: v["version"] for k, v in current["components"].items()},
                               runner=self.runner, now=self.clock(), metadata_only=True)
                if "host" in current["components"] and "host" not in metadata["components"]:
                    raise Refused("Host-enrolled appliances require a versioned host bundle for authorized integrity acceptance")
                if any(not component["rollback_safe"] for component in metadata["components"].values()):
                    raise Refused("Controlled migration release requires a database-specific recovery procedure")
                if metadata["declared_bytes"] > MAX_BUNDLE or shutil.disk_usage(self.state).free < metadata["declared_bytes"] * 4 + 1024**3:
                    raise Refused("Insufficient download and transaction reserve")
                for artifact in metadata["artifacts"]:
                    name = artifact["name"]
                    if name in {"manifest.json", "manifest.sig"} or name not in index or index[name]["size"] != artifact["bytes"]:
                        raise Refused("Signed artifact is missing or differs from its GitHub asset")
                self.record(policy, "downloading", release_id=release["id"], sequence=metadata["sequence"])
                for artifact in metadata["artifacts"]:
                    download(artifact["name"], artifact["bytes"], artifact["sha256"])
                verify_release(stage / "manifest.json", stage / "manifest.sig", self.public_key, stage,
                               current_sequence=current["sequence"], runner=self.runner, now=self.clock())
                self.record(policy, "installing", release_id=release["id"], sequence=metadata["sequence"])
                result = self.manager.install(stage / "manifest.json", stage / "manifest.sig", stage, self.public_key)
                if result.get("state") != "committed" or result.get("finalization") != "complete":
                    raise Refused("Update transaction has not completed all acceptance checks")
                return self.record(policy, "installed", release_id=release["id"], sequence=metadata["sequence"], version=metadata["version"])
            except Exception as exc:
                result = self.record(policy, "blocked" if isinstance(exc, Refused) else "failed", error_type=type(exc).__name__,
                                     **({"http_status": exc.status} if isinstance(exc, HTTPFailure) else {}))
                # Protected transaction receipts retain detailed recovery state;
                # URL query strings, credentials and subprocess errors are never published.
                return result
            finally:
                if stage is not None:
                    # Only our fresh download directory. UpdateManager retains its
                    # separately verified transaction copy for recovery/rollback.
                    shutil.rmtree(stage)


def main():
    try:
        require_linux_root()
        os.umask(0o077)
        policy, token = load_policy()
        result = GitHubUpdater(transport=GitHubTransport(token)).poll(policy)
        print(json.dumps(result, sort_keys=True))
        return 1 if result["status"] in {"blocked", "failed"} else 0
    except Exception:
        print(json.dumps({"status": "unavailable", "message": "GitHub update configuration or enrollment is unavailable"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
