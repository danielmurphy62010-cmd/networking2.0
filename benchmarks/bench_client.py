#!/usr/bin/env python3
"""Benchmark network2 ping, message latency and throughput."""
from __future__ import annotations

import argparse
import csv
import json
import multiprocessing as mp
import os
import statistics
import tempfile
import time
import uuid
from pathlib import Path

import network2

SIZES = [256 * 1024, 512 * 1024, 1 * 1024 * 1024,
         2 * 1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
         16 * 1024 * 1024]
PING_SIZE = 1024


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * p))]


def roundtrip(client, payload: bytes, timeout: float = 30.0) -> tuple[bytes, float]:
    start = time.perf_counter()
    eid = client.send(payload)
    response = client.recv(eid, timeout=timeout)
    elapsed = time.perf_counter() - start
    if response is None:
        raise TimeoutError(f"timed out waiting for EID {eid.hex()}")
    return bytes(response), elapsed


def latency_test(client, size: int, direction: str, samples: int) -> dict:
    times = []
    if direction == "ping":
        request = b"P" + bytes(size - 1)
        for _ in range(samples):
            response, elapsed = roundtrip(client, request)
            if len(response) != size:
                raise RuntimeError("ping response length mismatch")
            times.append(elapsed * 1000)
    elif direction == "upload":
        body = b"U" + bytes(size - 1)
        for _ in range(samples):
            response, elapsed = roundtrip(client, body)
            if response != b"ACK":
                raise RuntimeError("upload ACK mismatch")
            times.append(elapsed * 1000)
    else:
        request = b"D" + size.to_bytes(8, "big")
        for _ in range(samples):
            response, elapsed = roundtrip(client, request)
            if len(response) != size:
                raise RuntimeError(f"download length mismatch: {len(response)} != {size}")
            times.append(elapsed * 1000)
    return {
        "test": f"{direction}_latency",
        "size_bytes": size,
        "samples": len(times),
        "median_ms": statistics.median(times),
        "p95_ms": percentile(times, 0.95),
        "min_ms": min(times),
    }


def single_bandwidth_test(client, size: int, direction: str, samples: int) -> dict:
    rates = []
    latencies = []
    for _ in range(samples):
        if direction == "upload":
            payload = b"U" + bytes(size - 1)
        else:
            payload = b"D" + size.to_bytes(8, "big")
        response, elapsed = roundtrip(client, payload)
        if direction == "upload":
            if response != b"ACK":
                raise RuntimeError("upload ACK mismatch")
        elif len(response) != size:
            raise RuntimeError("download length mismatch")
        latencies.append(elapsed * 1000)
        rates.append(size / elapsed / (1024 * 1024))
    return {
        "test": f"single_message_{direction}_bandwidth",
        "size_bytes": size,
        "samples": samples,
        "median_mib_s": statistics.median(rates),
        "median_latency_ms": statistics.median(latencies),
    }


def continuous_test(client, size: int, direction: str, duration: float) -> dict:
    # Keep a bounded batch in flight: continuous throughput should not be
    # constrained to one request/response round trip at a time.
    window = 2
    deadline = time.perf_counter() + duration
    total_bytes = 0
    messages = 0
    if direction == "upload":
        payload = b"U" + bytes(size - 1)
    else:
        payload = b"D" + size.to_bytes(8, "big")

    start = time.perf_counter()
    while time.perf_counter() < deadline:
        pending = [client.send(payload) for _ in range(window)]
        for eid in pending:
            response = client.recv(eid, timeout=max(30.0, duration * 4))
            if response is None:
                raise TimeoutError(f"continuous {direction} response timed out")
            if direction == "upload":
                if bytes(response) != b"ACK":
                    raise RuntimeError("upload ACK mismatch")
            elif len(response) != size:
                raise RuntimeError("download length mismatch")
            total_bytes += size
            messages += 1

    elapsed = time.perf_counter() - start
    return {
        "test": f"continuous_{direction}_bandwidth",
        "size_bytes": size,
        "window": window,
        "duration_s": elapsed,
        "messages": messages,
        "total_mib": total_bytes / (1024 * 1024),
        "mib_s": total_bytes / elapsed / (1024 * 1024),
    }


def run_worker(worker_id: int, host: str, port: int, password: str,
               continuous_seconds: float, latency_samples: int,
               single_samples: int, output_queue) -> None:
    # Each process gets a private cwd because network2 persists client identity
    # material relative to the current working directory.
    workdir = Path(tempfile.gettempdir()) / f"network2-bench-{os.getpid()}-{uuid.uuid4().hex}"
    workdir.mkdir(parents=True, exist_ok=True)
    old_cwd = Path.cwd()
    try:
        os.chdir(workdir)
        client = network2.TCPClient(host, port, password, simult_exchanges=4)
        results = []
        try:
            if not client.is_authed():
                raise RuntimeError("client did not authenticate")
            # Warm the connection before recording measurements.
            roundtrip(client, b"P" + bytes(PING_SIZE - 1))
            results.append({"test": "ping_latency", **latency_test(
                client, PING_SIZE, "ping", latency_samples)})
            for size in SIZES:
                results.append(latency_test(client, size, "upload", latency_samples))
                results.append(latency_test(client, size, "download", latency_samples))
                results.append(single_bandwidth_test(client, size, "upload", single_samples))
                results.append(single_bandwidth_test(client, size, "download", single_samples))
                results.append(continuous_test(client, size, "upload", continuous_seconds))
                results.append(continuous_test(client, size, "download", continuous_seconds))
        finally:
            client.close()
        output_queue.put({"worker": worker_id, "ok": True, "results": results})
    except Exception as exc:
        output_queue.put({"worker": worker_id, "ok": False, "error": repr(exc)})
    finally:
        os.chdir(old_cwd)
        try:
            for child in workdir.iterdir():
                if child.is_file():
                    child.unlink()
            workdir.rmdir()
        except OSError:
            pass


def aggregate(worker_results: list[dict], clients: int) -> list[dict]:
    successful = [item for item in worker_results if item["ok"]]
    if not successful:
        return []
    grouped: dict[tuple, list[dict]] = {}
    for worker in successful:
        for row in worker["results"]:
            key = (row["test"], row.get("size_bytes"))
            grouped.setdefault(key, []).append(row)

    output = []
    for (test, size), rows in grouped.items():
        combined = {
            "clients": clients,
            "test": test,
            "size_bytes": size,
            "workers_completed": len(rows),
        }
        for field in ("median_ms", "p95_ms", "min_ms", "median_latency_ms"):
            values = [row[field] for row in rows if field in row]
            if values:
                combined[field] = statistics.mean(values)

        # Throughput is reported both per process and as the sum across all
        # successful client processes in this concurrency run.
        for field in ("median_mib_s", "mib_s"):
            values = [row[field] for row in rows if field in row]
            if values:
                combined["mean_client_" + field] = statistics.mean(values)
                combined["aggregate_mib_s"] = sum(values)
        for field in ("total_mib", "messages"):
            values = [row[field] for row in rows if field in row]
            if values:
                combined[field] = sum(values)
        output.append(combined)
    return output


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--password", required=True)
    parser.add_argument("--clients", nargs="+", type=int, default=[1, 10],
                        help="client process counts to run (default: 1 10)")
    parser.add_argument("--duration", type=float, default=2.0,
                        help="seconds per continuous throughput test")
    parser.add_argument("--latency-samples", type=int, default=10)
    parser.add_argument("--single-samples", type=int, default=3)
    parser.add_argument("--output", default="network2-benchmark")
    args = parser.parse_args()

    all_rows = []
    for count in args.clients:
        if count < 1:
            parser.error("client counts must be positive")
        print(f"\n=== Running with {count} client process(es) ===", flush=True)
        ctx = mp.get_context("spawn")
        queue = ctx.Queue()
        processes = [
            ctx.Process(target=run_worker,
                        args=(i, args.host, args.port, args.password,
                              args.duration, args.latency_samples,
                              args.single_samples, queue))
            for i in range(count)
        ]
        start = time.perf_counter()
        for process in processes:
            process.start()
        worker_results = [queue.get() for _ in processes]
        for process in processes:
            process.join()
        elapsed = time.perf_counter() - start
        failures = [item for item in worker_results if not item["ok"]]
        for failure in failures:
            print(f"worker {failure['worker']} failed: {failure['error']}", flush=True)
        rows = aggregate(worker_results, count)
        all_rows.extend(rows)
        print(f"completed {count - len(failures)}/{count} workers in {elapsed:.2f}s", flush=True)
        for row in rows:
            size = row.get("size_bytes")
            size_label = "1 KiB" if row["test"] == "ping_latency" else (
                f"{size / (1024 * 1024):g} MiB" if size else "")
            metric = row.get("median_ms", row.get("mib_s", row.get("median_mib_s", 0)))
            unit = "ms" if "latency" in row["test"] else "MiB/s"
            print(f"  {row['test']:38} {size_label:>8}  {metric:10.3f} {unit}", flush=True)

    base = Path(args.output)
    json_path = base.with_suffix(".json")
    csv_path = base.with_suffix(".csv")
    json_path.write_text(json.dumps(all_rows, indent=2), encoding="utf-8")
    write_csv(csv_path, all_rows)
    print(f"\nSaved {json_path} and {csv_path}", flush=True)


if __name__ == "__main__":
    mp.freeze_support()
    main()
