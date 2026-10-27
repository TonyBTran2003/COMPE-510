# COMPE-510 PCAP Processing

## Requirements

- Python 3.10+
- Wireshark's `editcap` utility (for converting PCAPNG to PCAP)
- Raw network capture files totaling at least 5 GiB
- `01_pcap_to_packets.py`
- `02_packets_to_timeseries.py`

Install `editcap` on Ubuntu/WSL:

```bash
sudo apt update
sudo apt install wireshark-common
```

## Folder Structure

```text
COMPE-510/
├── 01_pcap_to_packets.py
├── 02_packets_to_timeseries.py
├── README.md
├── .gitignore
├── data/
│   ├── raw/
│   │   └── Friday-WorkingHours.pcap          # Original PCAPNG capture
│   ├── converted/
│   │   └── Friday-WorkingHours-classic.pcap  # Converted classic PCAP
│   └── flow_labels/
│       └── *.csv                            # Optional flow-label datasets
└── output/                                  # Created by scripts
    ├── manifest.json
    ├── packet_tables/
    │   └── *.packets.csv.gz
    ├── time_series/
    │   └── windows_5s.csv.gz
    └── processing_report.json
```

## 1. Convert PCAPNG to PCAP

The original `Friday-WorkingHours.pcap` is in PCAPNG format. The first Python script requires classic PCAP.

From the `COMPE-510` folder:

```bash
# Check disk space before creating another large capture file
df -h .

mkdir -p data/converted

editcap -F pcap \
  data/raw/Friday-WorkingHours.pcap \
  data/converted/Friday-WorkingHours-classic.pcap

# Verify the converted file
file data/converted/Friday-WorkingHours-classic.pcap
```

## 2. Run Part 1 — PCAP to Packet Table

```bash
python3 01_pcap_to_packets.py --input data/converted --output output --target-gib 5
```

Output: `output/packet_tables/*.packets.csv.gz` and `output/manifest.json`.

## 3. Run Part 2 — 5-Second Time Series

```bash
python3 02_packets_to_timeseries.py --input output --window-seconds 5
```

Output: `output/time_series/windows_5s.csv.gz` and `output/processing_report.json`.

## 4. Check Results

```bash
cat output/processing_report.json
```

Keep `data/raw/`, `data/converted/`, `data/flow_labels/`, and `output/` out of Git using `.gitignore`.
