#!/usr/bin/env python3
"""Bounded, opt-in development listener benchmark (Python standard library only).

Writes explicit synthetic records to the configured running collector and checks
its real ClickHouse database. No real firewall configuration is changed. Reads
private local development credentials; never prints them. See docs/INGEST_BENCHMARK.md.
"""
import argparse
import base64
import csv
import datetime as dt
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
SERIAL = "BENCHMARK-INGEST"
UTC = dt.timezone.utc


def utcnow():
    return dt.datetime.now(UTC).isoformat(timespec="milliseconds")


class Benchmark:
    def __init__(self, args):
        self.args = args
        self.env_path = ROOT / ".local/dev.env"
        self.token_path = ROOT / ".local/test-access-token"
        self.run_id = uuid.uuid4().hex
        self.session_base = time.time_ns() // 1000
        self.timezone = ZoneInfo("US/Pacific")
        self.stop_monitor = threading.Event()
        self.receipt = {"run_id": self.run_id, "started_at": utcnow(), "synthetic_serial": SERIAL,
                        "host": args.host, "stages": [], "samples": [], "status": "running",
                        "measurement_scope": "Local Docker development; concurrent live firewall input"}
        self.output = ROOT / ".local" / ("ingest-benchmark-" + self.run_id + ".json")
        fixture = (ROOT / "internal/panos/testdata/pa1410-12.1-traffic.log").read_text().strip()
        self.fields = next(csv.reader([fixture.split("lab-fw ", 1)[1]]))
        assert len(self.fields) == 130

    def save(self):
        self.output.parent.mkdir(mode=0o700, exist_ok=True)
        with os.fdopen(os.open(self.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump(self.receipt, f, indent=2)
            f.write("\n")

    def token_remaining(self):
        token = self.token_path.read_text().strip()
        payload = token.split(".")[1]
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return int(data["exp"] - time.time())

    def api_json(self, path):
        req = urllib.request.Request(self.args.api + path, headers={
            "Authorization": "Bearer " + self.token_path.read_text().strip()})
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise RuntimeError("Collector API HTTP status " + str(exc.code)) from None

    def stats(self):
        return self.api_json("/api/stats")

    def query(self, sql, **params):
        env = dict(line.split("=", 1) for line in self.env_path.read_text().splitlines()
                   if "=" in line and not line.startswith("#"))
        query = {"database": "nebulalog", "max_execution_time": "10", "max_memory_usage": "268435456",
                 "output_format_json_quote_64bit_integers": "0", "date_time_output_format": "iso"}
        query.update({"param_" + k: str(v) for k, v in params.items()})
        req = urllib.request.Request(self.args.clickhouse + "/?" + urllib.parse.urlencode(query),
                                     data=(sql + " FORMAT JSONEachRow").encode(), method="POST", headers={
                                         "Authorization": "Basic " + base64.b64encode(
                                             ("nebulalog:" + env["CH_PASSWORD"]).encode()).decode()})
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                return [json.loads(line) for line in response if line.strip()]
        except urllib.error.HTTPError as exc:
            raise RuntimeError("ClickHouse HTTP status " + str(exc.code)) from None

    def disk(self):
        host = shutil.disk_usage(ROOT)
        disks = self.query("SELECT name, free_space, total_space FROM system.disks")
        parts = self.query("SELECT count() parts, sum(rows) rows, sum(bytes_on_disk) bytes_on_disk "
                           "FROM system.parts WHERE database='nebulalog' AND table='events' AND active")[0]
        return {"host_free_bytes": host.free, "clickhouse_disks": disks, "event_parts": parts}

    def resources(self):
        r = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{json .}}",
                            "nebulalog-dev-app-1", "nebulalog-dev-clickhouse-1"],
                           capture_output=True, text=True, timeout=10, check=True)
        return [json.loads(line) for line in r.stdout.splitlines() if line]

    def monitor(self):
        while not self.stop_monitor.is_set():
            sample = {"at": utcnow()}
            try:
                sample["stats"] = self.stats()
                sample["docker"] = self.resources()
            except Exception as exc:
                sample["measurement_error"] = type(exc).__name__
            self.receipt["samples"].append(sample)
            self.stop_monitor.wait(5)

    def payload(self, stage, index):
        now = dt.datetime.now(UTC)
        local = now.astimezone(self.timezone)
        fields = self.fields.copy()
        fields[1] = fields[6] = local.strftime("%Y/%m/%d %H:%M:%S")
        fields[2] = SERIAL
        fields[7] = "192.0.2." + str(1 + index % 250)
        fields[11] = stage["rule"]
        fields[12] = "EXAMPLE\\benchmark"
        fields[20] = "NebulaLog-benchmark"
        fields[22] = str(stage["session_base"] + index)
        fields[24] = str(40000 + index % 20000)
        fields[35] = (local - dt.timedelta(seconds=2)).strftime("%Y/%m/%d %H:%M:%S")
        fields[36] = "2"
        fields[39] = str(stage["session_base"] + index)
        fields[52] = "benchmark-ingest"
        fields[102] = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        out = io.StringIO(newline="")
        csv.writer(out, lineterminator="").writerow(fields)
        header = "<14>" + local.strftime("%b %e %H:%M:%S") + " benchmark-ingest "
        return (header + out.getvalue()).encode()

    def stage(self, name, count):
        stage = {"name": name, "rule": "benchmark-" + self.run_id + "-" + name,
                 "session_base": self.session_base + len(self.receipt["stages"]) * 1000000,
                 "expected": count, "sent": 0, "started_at": utcnow(), "before": self.stats()}
        self.receipt["stages"].append(stage)
        return stage

    def counts(self, stage):
        return self.query("SELECT count() count, uniqExact(session_id) unique_sessions, "
                          "countIf(parse_status='parsed') parsed FROM events "
                          "WHERE serial={serial:String} AND rule={rule:String}",
                          serial=SERIAL, rule=stage["rule"])[0]

    def verify(self, stage, golden):
        start = time.monotonic()
        deadline = start + self.args.drain_timeout
        while time.monotonic() < deadline:
            found = self.counts(stage)
            stats = self.stats()
            if found["count"] > stage["sent"]:
                raise AssertionError("Duplicate stored records in " + stage["name"])
            if found["count"] == stage["sent"] and stats["queue_depth"] == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Exact persisted count and empty queue not reached for " + stage["name"])
        assert found["count"] == found["unique_sessions"] == found["parsed"] == stage["sent"]
        stage["persisted"] = found
        stage["drain_seconds"] = round(time.monotonic() - start, 3)
        stage["after"] = stats
        stage["dropped_delta"] = stats["messages_dropped"] - stage["before"]["messages_dropped"]
        assert stage["dropped_delta"] == 0, "Collector reported dropped messages"
        assert stats["messages_received"] >= stage["before"]["messages_received"], "Collector restarted"
        rows = self.query("SELECT session_id, raw, parse_status, src_ip, dst_ip, src_port, dst_port, app, "
                          "action, subtype, received_at FROM events WHERE serial={serial:String} "
                          "AND rule={rule:String} ORDER BY toUInt64(session_id) LIMIT 5",
                          serial=SERIAL, rule=stage["rule"])
        assert len(rows) == len(golden)
        for index, row in enumerate(rows):
            assert row["raw"].encode() == golden[index], "Original raw payload changed"
            assert row["parse_status"] == "parsed" and row["session_id"] == str(stage["session_base"] + index)
            assert row["app"] == "dns-base" and row["action"] == "allow" and row["subtype"] == "end"
            assert row["src_ip"] == "192.0.2." + str(1 + index % 250)
            assert row["dst_ip"] == "2001:db8::53" and row["dst_port"] == 53
        stage["raw_and_normalized_checks"] = len(rows)
        stage["finished_at"] = utcnow()
        stage["status"] = "passed"
        self.save()
        print(json.dumps({"stage": stage["name"], "sent": stage["sent"], "persisted": found,
                          "send_elapsed_seconds": stage.get("send_elapsed_seconds"),
                          "achieved_send_eps": stage.get("achieved_send_eps"),
                          "drain_seconds": stage["drain_seconds"], "drops": stage["dropped_delta"]}), flush=True)

    def tcp(self, eps, seconds):
        stage = self.stage("tcp-" + str(eps), eps * seconds)
        stage.update(target_eps=eps, target_seconds=seconds, framing="LF")
        golden = []
        with socket.create_connection((self.args.host, self.args.tcp_port), timeout=10) as conn:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            start = time.monotonic()
            while stage["sent"] < stage["expected"]:
                elapsed = time.monotonic() - start
                if elapsed > seconds + 60:
                    raise TimeoutError("TCP producer exceeded bounded duration")
                due = min(stage["expected"], int(elapsed * eps) + 1)
                if due <= stage["sent"]:
                    time.sleep(min(0.01, (stage["sent"] / eps) - elapsed))
                    continue
                # A 10 ms scheduling tick can coalesce records; each has its own LF frame.
                batch = []
                for _ in range(min(due - stage["sent"], 256)):
                    raw = self.payload(stage, stage["sent"])
                    if stage["sent"] < 5:
                        golden.append(raw)
                    batch.append(raw + b"\n")
                    stage["sent"] += 1
                conn.sendall(b"".join(batch))
            remaining = seconds - (time.monotonic() - start)
            if remaining > 0:
                time.sleep(remaining)
            elapsed = time.monotonic() - start
            conn.shutdown(socket.SHUT_WR)
        stage["send_elapsed_seconds"] = round(elapsed, 4)
        stage["achieved_send_eps"] = round(stage["sent"] / elapsed, 2)
        stage["at_send_complete"] = {"persisted": self.counts(stage), "stats": self.stats()}
        self.verify(stage, golden)
        stage["end_to_end_seconds"] = round(time.monotonic() - start, 4)
        stage["persisted_end_to_end_eps"] = round(stage["sent"] / stage["end_to_end_seconds"], 2)
        self.save()

    def transport(self, transport):
        stage = self.stage(transport, 5)
        golden = [self.payload(stage, n) for n in range(5)]
        if transport == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
                for raw in golden:
                    assert conn.sendto(raw, (self.args.host, self.args.tcp_port)) == len(raw)
                    stage["sent"] += 1
                    time.sleep(0.02)
            stage["framing"] = "one datagram per message"
        else:
            context = ssl.create_default_context(cafile=str(ROOT / ".local/certs/syslog.crt"))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((self.args.host, self.args.tls_port), timeout=10) as tcp:
                # Development certificate explicitly names localhost; trust + name are both verified.
                with context.wrap_socket(tcp, server_hostname="localhost") as conn:
                    stage["tls_protocol"] = conn.version()
                    stage["tls_cipher"] = conn.cipher()[0]
                    for raw in golden:
                        conn.sendall(str(len(raw)).encode() + b" " + raw)
                        stage["sent"] += 1
                    time.sleep(0.1)
            stage["framing"] = "RFC 5425 octet counting"
            stage["certificate_chain_and_hostname_verified"] = True
        self.verify(stage, golden)

    def invalid(self):
        raw = ("NEBULALOG-INVALID-" + self.run_id + " deliberately malformed syslog").encode()
        before = self.stats()
        started_at = utcnow()
        with socket.create_connection((self.args.host, self.args.tcp_port), timeout=10) as conn:
            conn.sendall(raw + b"\n")
        deadline = time.monotonic() + self.args.drain_timeout
        while time.monotonic() < deadline:
            rows = self.query("SELECT raw, parse_status, parse_error FROM events WHERE raw={raw:String}",
                              raw=raw.decode())
            if rows:
                break
            time.sleep(0.2)
        assert len(rows) == 1 and rows[0]["raw"].encode() == raw
        assert rows[0]["parse_status"] == "failed" and rows[0]["parse_error"]
        after = self.stats()
        assert after["messages_dropped"] == before["messages_dropped"]
        diagnostics = self.api_json("/api/logs?" + urllib.parse.urlencode({"type": "parsing", "from": started_at, "limit": 1000}))
        assert any(row["raw"].encode() == raw and row["parse_error"] for row in diagnostics["events"])
        self.receipt["invalid_raw"] = {"count": 1, "raw_preserved": True, "visible_in_diagnostics_api": True,
                                       "parse_status": rows[0]["parse_status"], "diagnostic_present": True}
        print("Invalid raw payload retained with an explicit parser diagnostic.", flush=True)

    def run(self):
        if self.token_remaining() < 180:
            raise RuntimeError("Refresh private browser-issued API token before starting (need 180 seconds remaining)")
        self.receipt["before"] = {"stats": self.stats(), "disk": self.disk(), "docker": self.resources()}
        disk = self.receipt["before"]["disk"]
        if disk["host_free_bytes"] < 5 * 1024**3 or any(d["free_space"] < 5 * 1024**3 for d in disk["clickhouse_disks"]):
            raise RuntimeError("Insufficient disk reserve (minimum 5 GiB free)")
        thread = threading.Thread(target=self.monitor, daemon=True)
        thread.start()
        try:
            print("Starting bounded TCP stages; synthetic identity BENCHMARK-INGEST.", flush=True)
            self.tcp(265, 60)
            self.tcp(2650, 10)
            self.transport("udp")
            self.transport("tls")
            self.invalid()
            # Recheck all staged counts after every transport has completed.
            for stage in self.receipt["stages"]:
                assert self.counts(stage) == stage["persisted"], "Late count changed"
            self.receipt["after"] = {"stats": self.stats(), "disk": self.disk(), "docker": self.resources()}
            assert self.receipt["after"]["stats"]["messages_dropped"] == self.receipt["before"]["stats"]["messages_dropped"]
            self.receipt["status"] = "passed"
        except Exception as exc:
            self.receipt["status"] = "failed"
            self.receipt["failure_type"] = type(exc).__name__
            raise
        finally:
            self.stop_monitor.set()
            thread.join(timeout=12)
            self.receipt["finished_at"] = utcnow()
            self.save()
            print("Private receipt: " + str(self.output), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="Explicit disposable collector host for synthetic test traffic")
    parser.add_argument("--tcp-port", type=int, default=5514)
    parser.add_argument("--tls-port", type=int, default=6514)
    parser.add_argument("--api", default="http://127.0.0.1:18080")
    parser.add_argument("--clickhouse", default="http://127.0.0.1:28123")
    parser.add_argument("--drain-timeout", type=int, default=90)
    args = parser.parse_args()
    if not 1 <= args.drain_timeout <= 120:
        parser.error("drain timeout must be between 1 and 120 seconds")
    Benchmark(args).run()


if __name__ == "__main__":
    main()
