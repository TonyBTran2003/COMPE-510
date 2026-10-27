# COMPE-510 PCAP Processing

## Requirements

- Python 3.10+
- Raw `.pcap` files (at least 5 GiB total)
- `01_pcap_to_packets.py`
- `02_packets_to_timeseries.py`

## Folder Structure

```text
COMPE-510/
├── 01_pcap_to_packets.py
├── 02_packets_to_timeseries.py
├── README.md
├── data/
│   ├── raw/
│   │   └── *.pcap
│   └── flow_labels/
│       └── *.csv          # Optional; not used by these scripts
└── output/                # Created automatically
    ├── manifest.json
    ├── packet_tables/
    ├── time_series/
    │   └── windows_5s.csv.gz
    └── processing_report.json
```

## Setup

Place the original `.pcap` files in `data/raw/`.

**Note:** Files ending in `.pcap_ISCX.csv` are not raw `.pcap` files. Keep them in `data/flow_labels/`.

## Run

From the `COMPE-510` folder:

### Part 1: PCAP to Packet Table

```bash
python3 01_pcap_to_packets.py --input data/raw --output output --target-gib 5
```

### Part 2: Packet Table to 5-Second Time Series

```bash
python3 02_packets_to_timeseries.py --input output --window-seconds 5
```

### View Results

```bash
cat output/processing_report.json
```

## Output Files

| File | Contents |
| --- | --- |
| `output/packet_tables/*.packets.csv.gz` | One row per packet |
| `output/time_series/windows_5s.csv.gz` | One row per nonempty 5-second window |
| `output/processing_report.json` | Data size and reduction results |

## Test With a Small PCAP

```bash
python3 01_pcap_to_packets.py --input data/raw --output output --target-gib 0
python3 02_packets_to_timeseries.py --input output --window-seconds 5
```
