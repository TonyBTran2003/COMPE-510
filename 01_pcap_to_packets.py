"""Part 1: Convert classic .pcap capture files into compressed packet tables.

The parser streams one packet at a time and does not load the capture into RAM.
Supported: classic PCAP (microsecond or nanosecond timestamps), Ethernet,
IPv4, IPv6, TCP, UDP, and ICMP. PCAPNG is intentionally not supported.
"""

import argparse
import csv
import gzip
import hashlib
import ipaddress
import json
import struct
from pathlib import Path

GIB = 1024**3
MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1),      # Little-endian, microseconds.
    b"\xa1\xb2\xc3\xd4": (">", 1),      # Big-endian, microseconds.
    b"\x4d\x3c\xb2\xa1": ("<", 1000),   # Little-endian, nanoseconds.
    b"\xa1\xb2\x3c\x4d": (">", 1000),   # Big-endian, nanoseconds.
}
HEADERS = [
    "timestamp_us", "frame_bytes", "captured_bytes", "ip_version",
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "payload_bytes", "tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst",
]


def read_pcap(path):
    """Yield (timestamp in microseconds, captured frame, original size, linktype)."""
    with path.open("rb", buffering=2 * 1024 * 1024) as capture:
        magic = capture.read(4)
        if magic not in MAGIC:
            raise ValueError(f"{path}: unsupported capture format (expected classic .pcap)")

        endian, ns_per_unit = MAGIC[magic]
        global_header = capture.read(20)
        if len(global_header) != 20:
            raise ValueError(f"{path}: truncated PCAP global header")
        _, _, _, _, snaplen, network = struct.unpack(endian + "HHiIII", global_header)
        linktype = network & 0xFFFF
        packet_header = struct.Struct(endian + "IIII")

        while True:
            header = capture.read(16)
            if not header:
                break
            if len(header) != 16:
                raise ValueError(f"{path}: truncated packet header")
            seconds, fraction, captured_len, original_len = packet_header.unpack(header)
            if captured_len > max(snaplen, 16 * 1024 * 1024):
                raise ValueError(f"{path}: invalid packet length: {captured_len}")
            frame = capture.read(captured_len)
            if len(frame) != captured_len:
                raise ValueError(f"{path}: truncated packet data")

            # Integer timestamps avoid rounding across 5-second boundaries.
            timestamp_us = seconds * 1_000_000 + fraction // ns_per_unit
            yield timestamp_us, frame, original_len, linktype


def network_offset(frame, linktype):
    """Find the IP header and its EtherType, supporting common link layers."""
    if linktype == 1 and len(frame) >= 14:  # Ethernet (with optional VLAN tags).
        kind = int.from_bytes(frame[12:14], "big")
        offset = 14
        for _ in range(4):
            if kind not in (0x8100, 0x88A8, 0x9100) or len(frame) < offset + 4:
                break
            kind = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4
        return offset, kind
    if linktype == 113 and len(frame) >= 16:  # Linux cooked capture (SLL).
        return 16, int.from_bytes(frame[14:16], "big")
    if linktype == 101 and frame:  # Raw IP packet.
        version = frame[0] >> 4
        return 0, {4: 0x0800, 6: 0x86DD}.get(version, 0)
    return len(frame), 0


def ip_addresses(frame, offset, kind):
    """Return IP addresses, IP protocol, and transport-data boundaries."""
    if kind == 0x0800 and len(frame) >= offset + 20:
        ip = frame[offset:]
        version, header_len = ip[0] >> 4, (ip[0] & 15) * 4
        if version != 4 or header_len < 20 or len(ip) < header_len:
            return None
        declared_len = int.from_bytes(ip[2:4], "big")
        end = min(len(frame), offset + declared_len) if declared_len else len(frame)
        flags_and_offset = int.from_bytes(ip[6:8], "big")
        later_fragment = bool(flags_and_offset & 0x1FFF)
        return (
            4, str(ipaddress.IPv4Address(ip[12:16])),
            str(ipaddress.IPv4Address(ip[16:20])),
            ip[9], offset + header_len, end, later_fragment,
        )

    if kind == 0x86DD and len(frame) >= offset + 40:
        ip = frame[offset:]
        if ip[0] >> 4 != 6:
            return None
        data_end = min(len(frame), offset + 40 + int.from_bytes(ip[4:6], "big"))
        proto = ip[6]
        data_start = offset + 40
        later_fragment = False
        # Skip common IPv6 extension headers to locate TCP/UDP/ICMPv6.
        for _ in range(8):
            if proto not in (0, 43, 44, 51, 60) or data_start + 2 > data_end:
                break
            next_proto = frame[data_start]
            ext_length = frame[data_start + 1]
            if proto == 44:
                if data_start + 8 > data_end:
                    break
                later_fragment = bool(int.from_bytes(frame[data_start + 2:data_start + 4], "big") & 0xFFF8)
                length = 8
            elif proto == 51:
                length = (ext_length + 2) * 4
            else:
                length = (ext_length + 1) * 8
            if data_start + length > data_end:
                break
            proto = next_proto
            data_start += length
        return (
            6, str(ipaddress.IPv6Address(ip[8:24])),
            str(ipaddress.IPv6Address(ip[24:40])),
            proto, data_start, data_end, later_fragment,
        )
    return None


def extract_packet(timestamp_us, frame, frame_bytes, linktype):
    """Parse useful headers, retaining a row even for non-IP traffic."""
    record = {
        "timestamp_us": timestamp_us,
        "frame_bytes": frame_bytes,
        "captured_bytes": len(frame),
        "ip_version": "", "src_ip": "", "dst_ip": "",
        "src_port": "", "dst_port": "", "protocol": "NON_IP",
        "payload_bytes": 0,
        "tcp_syn": 0, "tcp_ack": 0, "tcp_fin": 0, "tcp_rst": 0,
    }
    offset, kind = network_offset(frame, linktype)
    parsed = ip_addresses(frame, offset, kind)
    if parsed is None:
        return record

    version, src_ip, dst_ip, proto, start, end, later_fragment = parsed
    record.update(ip_version=version, src_ip=src_ip, dst_ip=dst_ip)
    record["protocol"] = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(proto, "OTHER")

    if later_fragment:  # Non-initial IP fragments have no transport headers.
        return record
    if proto == 6 and end >= start + 20:
        tcp_header_size = (frame[start + 12] >> 4) * 4
        if tcp_header_size < 20 or start + tcp_header_size > end:
            return record
        flags = frame[start + 13]
        record.update(
            src_port=int.from_bytes(frame[start:start + 2], "big"),
            dst_port=int.from_bytes(frame[start + 2:start + 4], "big"),
            payload_bytes=max(0, end - (start + tcp_header_size)),
            tcp_syn=int(bool(flags & 0x02)),
            tcp_ack=int(bool(flags & 0x10)),
            tcp_fin=int(bool(flags & 0x01)),
            tcp_rst=int(bool(flags & 0x04)),
        )
    elif proto == 17 and end >= start + 8:
        record.update(
            src_port=int.from_bytes(frame[start:start + 2], "big"),
            dst_port=int.from_bytes(frame[start + 2:start + 4], "big"),
            payload_bytes=max(0, end - (start + 8)),
        )
    elif proto in (1, 58) and end >= start + 4:
        record["payload_bytes"] = max(0, end - start - 4)
    return record


def list_captures(folder):
    if folder.is_file():
        return [folder] if folder.suffix.lower() == ".pcap" else []
    return sorted(path for path in folder.rglob("*") if path.suffix.lower() == ".pcap")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="A .pcap file or folder of .pcap files")
    parser.add_argument("--output", type=Path, default=Path("output"), help="Project output directory")
    parser.add_argument("--target-gib", type=float, default=5.0, help="Minimum input size in GiB (default: 5)")
    parser.add_argument("--all", action="store_true", help="Process every capture instead of stopping at target size")
    args = parser.parse_args()

    if args.target_gib < 0:
        parser.error("--target-gib cannot be negative")
    if not args.input.exists():
        parser.error(f"Input path does not exist: {args.input}")
    candidates = list_captures(args.input)
    if not candidates:
        parser.error("No classic .pcap files found; extract/download the raw PCAPs first")

    selected = []
    total_size = 0
    threshold = args.target_gib * GIB
    for path in candidates:
        if not args.all and selected and total_size >= threshold:
            break
        selected.append(path)
        total_size += path.stat().st_size
    if total_size < threshold:
        parser.error(f"Only {total_size / GIB:.2f} GiB of PCAP available; the target is {args.target_gib:g} GiB")

    packet_folder = args.output / "packet_tables"
    packet_folder.mkdir(parents=True, exist_ok=True)
    manifest = {"raw_bytes": total_size, "target_gib": args.target_gib, "files": [], "packet_rows": 0}

    for index, pcap_path in enumerate(selected, 1):
        relative = pcap_path.relative_to(args.input) if args.input.is_dir() else Path(pcap_path.name)
        identifier = hashlib.sha1(str(relative).encode()).hexdigest()[:8]
        filename = f"{pcap_path.stem}-{identifier}.packets.csv.gz"
        destination = packet_folder / filename
        rows = 0
        print(f"[{index}/{len(selected)}] Reading {relative} ({pcap_path.stat().st_size / GIB:.2f} GiB)", flush=True)
        try:
            with gzip.open(destination, "wt", newline="", encoding="utf-8", compresslevel=3) as outfile:
                writer = csv.DictWriter(outfile, fieldnames=HEADERS)
                writer.writeheader()
                for timestamp, frame, original_len, linktype in read_pcap(pcap_path):
                    writer.writerow(extract_packet(timestamp, frame, original_len, linktype))
                    rows += 1
                    if rows % 1_000_000 == 0:
                        print(f"    {rows:,} packets", flush=True)
        except Exception:
            destination.unlink(missing_ok=True)
            raise

        manifest["packet_rows"] += rows
        manifest["files"].append({
            "source": str(relative), "raw_bytes": pcap_path.stat().st_size,
            "packet_table": filename, "packet_rows": rows,
            "packet_table_bytes": destination.stat().st_size,
        })
        print(f"    Finished: {rows:,} packets -> {destination}", flush=True)

    manifest_path = args.output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nPart 1 complete: {manifest['packet_rows']:,} packets from {total_size / GIB:.2f} GiB of raw captures")
    print(f"Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
