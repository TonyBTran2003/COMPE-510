"""Part 2: Aggregate packet CSV tables into one row per 5-second interval.

Streams compressed rows with a small lateness buffer, keeping memory usage low.
Each capture has separate windows; unlabeled output is NOT a training target yet.
"""

import argparse
import csv
import gzip
import json
import math
from datetime import datetime, timezone
from pathlib import Path

GIB = 1024**3
HEADERS = [
    "capture_file", "window_start_utc", "window_start_us", "window_seconds",
    "packet_count", "total_bytes", "packets_per_second", "bytes_per_second",
    "mean_packet_bytes", "std_packet_bytes", "min_packet_bytes", "max_packet_bytes",
    "payload_bytes", "payload_packet_count", "tcp_count", "udp_count", "icmp_count",
    "other_count", "syn_count", "ack_count", "fin_count", "rst_count",
]


def create_window():
    # Track simple statistics instead of storing the packets themselves.
    return {
        "count": 0, "bytes": 0, "bytes_squared": 0,
        "min_bytes": float("inf"), "max_bytes": 0,
        "payload_bytes": 0, "payload_packet_count": 0,
        "tcp_count": 0, "udp_count": 0, "icmp_count": 0, "other_count": 0,
        "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0,
    }


def update_window(stats, row):
    size = int(row["frame_bytes"])
    payload = int(row["payload_bytes"])
    stats["count"] += 1
    stats["bytes"] += size
    stats["bytes_squared"] += size * size
    stats["min_bytes"] = min(stats["min_bytes"], size)
    stats["max_bytes"] = max(stats["max_bytes"], size)
    stats["payload_bytes"] += payload
    stats["payload_packet_count"] += int(payload > 0)

    protocol = row["protocol"]
    if protocol == "TCP":
        stats["tcp_count"] += 1
    elif protocol == "UDP":
        stats["udp_count"] += 1
    elif protocol in ("ICMP", "ICMPv6"):
        stats["icmp_count"] += 1
    else:
        stats["other_count"] += 1

    for short, long_name in (("syn", "tcp_syn"), ("ack", "tcp_ack"),
                             ("fin", "tcp_fin"), ("rst", "tcp_rst")):
        stats[f"{short}_count"] += int(row[long_name])


def format_window(capture_file, start, seconds, stats):
    count = stats["count"]
    avg = stats["bytes"] / count
    std = math.sqrt(max(0.0, stats["bytes_squared"] / count - avg * avg))
    start_utc = datetime.fromtimestamp(start / 1_000_000, timezone.utc).isoformat()
    return {
        "capture_file": capture_file,
        "window_start_utc": start_utc,
        "window_start_us": start,
        "window_seconds": seconds,
        "packet_count": count,
        "total_bytes": stats["bytes"],
        "packets_per_second": count / seconds,
        "bytes_per_second": stats["bytes"] / seconds,
        "mean_packet_bytes": round(avg, 4),
        "std_packet_bytes": round(std, 4),
        "min_packet_bytes": stats["min_bytes"],
        "max_packet_bytes": stats["max_bytes"],
        "payload_bytes": stats["payload_bytes"],
        "payload_packet_count": stats["payload_packet_count"],
        "tcp_count": stats["tcp_count"],
        "udp_count": stats["udp_count"],
        "icmp_count": stats["icmp_count"],
        "other_count": stats["other_count"],
        "syn_count": stats["syn_count"],
        "ack_count": stats["ack_count"],
        "fin_count": stats["fin_count"],
        "rst_count": stats["rst_count"],
    }


def aggregate_file(path, capture_name, writer, seconds, lateness_seconds):
    # A small buffer allows slightly out-of-order timestamps in PCAP captures.
    width_us = seconds * 1_000_000
    lateness_us = lateness_seconds * 1_000_000
    active = {}
    last_flushed = None
    latest_us = 0
    total_packets = 0
    total_windows = 0

    with gzip.open(path, "rt", newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            timestamp = int(row["timestamp_us"])
            start = (timestamp // width_us) * width_us
            if last_flushed is not None and start <= last_flushed:
                raise ValueError(
                    f"{path}: timestamps are out of order beyond {lateness_seconds}s. "
                    "Increase --max-lateness-seconds or sort the packet table."
                )
            # Create each window's counters only once (important for millions of packets).
            if start not in active:
                active[start] = create_window()
            update_window(active[start], row)
            total_packets += 1
            latest_us = max(latest_us, timestamp)

            # A window is safe to write once packets can no longer arrive for it.
            cutoff = latest_us - lateness_us
            ready = [key for key in active if key + width_us <= cutoff]
            for key in sorted(ready):
                writer.writerow(format_window(capture_name, key, seconds, active.pop(key)))
                last_flushed = key
                total_windows += 1

    for key in sorted(active):
        writer.writerow(format_window(capture_name, key, seconds, active[key]))
        total_windows += 1
    return total_packets, total_windows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("output"), help="Output directory from Part 1")
    parser.add_argument("--window-seconds", type=int, default=5, help="Summary interval in seconds (default: 5)")
    parser.add_argument("--max-lateness-seconds", type=int, default=30, help="Buffer for out-of-order packets (default: 30)")
    args = parser.parse_args()
    if args.window_seconds <= 0 or args.max_lateness_seconds < 0:
        parser.error("Window size must be positive and allowed lateness cannot be negative")

    manifest_path = args.input / "manifest.json"
    if not manifest_path.is_file():
        parser.error("manifest.json was not found; run 01_pcap_to_packets.py first")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not manifest["files"]:
        parser.error("No packet files in manifest")

    output_folder = args.input / "time_series"
    output_folder.mkdir(parents=True, exist_ok=True)
    result = output_folder / f"windows_{args.window_seconds}s.csv.gz"
    packet_rows = 0
    window_rows = 0

    # Write only observed windows; no artificial empty/zero-traffic rows.
    with gzip.open(result, "wt", newline="", encoding="utf-8", compresslevel=6) as outfile:
        writer = csv.DictWriter(outfile, fieldnames=HEADERS)
        writer.writeheader()
        for info in manifest["files"]:
            path = args.input / "packet_tables" / info["packet_table"]
            print(f"Summarizing {info['source']} ...", flush=True)
            packets, windows = aggregate_file(
                path, info["source"], writer,
                args.window_seconds, args.max_lateness_seconds,
            )
            if packets != info["packet_rows"]:
                raise ValueError(f"Row count mismatch in {path}: {packets} != {info['packet_rows']}")
            packet_rows += packets
            window_rows += windows
            print(f"    {packets:,} packets -> {windows:,} time windows", flush=True)

    original_bytes = manifest["raw_bytes"]
    final_bytes = result.stat().st_size
    ratio = final_bytes / original_bytes if original_bytes else 0.0
    target_reached = original_bytes >= manifest["target_gib"] * GIB
    reduced_90_pct = ratio <= 0.10
    row_ratio = window_rows / packet_rows if packet_rows else 0.0
    report = {
        "raw_pcap_bytes": original_bytes,
        "raw_pcap_gib": round(original_bytes / GIB, 4),
        "packet_rows": packet_rows,
        "time_window_rows": window_rows,
        "window_seconds": args.window_seconds,
        "training_table_bytes": final_bytes,
        "training_table_mib": round(final_bytes / 1024**2, 4),
        "size_ratio": round(ratio, 6),
        "reduction_pct": round((1 - ratio) * 100, 4),
        "row_ratio": round(row_ratio, 6),
        "row_reduction_pct": round((1 - row_ratio) * 100, 4),
        "row_reduction_goal_passed": row_ratio <= 0.10,
        "raw_data_goal_passed": target_reached,
        "table_reduction_goal_passed": reduced_90_pct,
        "labels_available": False,
    }
    report_path = args.input / "processing_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\nPart 2 complete!")
    print(f"Final table: {result}")
    print(f"Input PCAP size: {original_bytes / GIB:.2f} GiB")
    print(f"Training table size: {final_bytes / 1024**2:.2f} MiB")
    print(f"Final-table size reduction: {(1 - ratio) * 100:.2f}%")
    print(f"Packet-to-window row reduction: {(1 - row_ratio) * 100:.2f}%")
    print(f"5 GiB target: {'PASS' if target_reached else 'FAIL'}")
    print(f"90% reduction target: {'PASS' if reduced_90_pct else 'FAIL'}")
    print(f"Report: {report_path}")


if __name__ == "__main__":
    main()
