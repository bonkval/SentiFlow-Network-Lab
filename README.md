# SentiFlow — Network Lab

SentiFlow is a local, Windows-friendly network threat monitor built for transparent, portfolio-ready security testing. It provides a live SOC-style dashboard, a normalized event pipeline, SQLite persistence, deterministic attack simulations, explainable detections, and optional TShark/Npcap capture or PCAP ingestion.

## Features

- Editable Traffic Lab with eight labeled benign and malicious scenarios
- Port scan, host discovery, brute force, beaconing, exfiltration, DNS anomaly, and indicator-match detections
- Event normalization shared by simulations, PCAP analysis, and live capture
- Explainable incidents with observed evidence and detection thresholds
- Local SQLite storage and incident workflow states
- Responsive Bootstrap dashboard with a VS Code-inspired traffic editor
- No paid services, cloud account, or third-party Python packages required

## Quick start

Requirements: Windows and Python 3.11 or newer.

1. Double-click `start-monitor.bat`.
2. Open <http://127.0.0.1:8000> if the browser does not open automatically.
3. Open **Traffic Lab**.
4. Select an example, inspect or edit its JSON, and choose **Analyze traffic**.

Stop the server by pressing `Ctrl+C` in its terminal window.

## Traffic Lab

The built-in library includes:

- Port scan
- Host discovery
- SSH brute force
- Command-and-control-style beaconing
- Possible data exfiltration
- DNS tunnelling pattern
- Threat-indicator match
- Normal browsing baseline

Each example loads actual normalized events into an editable JSON Lines workspace. Events are submitted individually through `POST /api/events`, validated, stored, correlated, and evaluated before an incident can be created.

The interface visibly follows four stages:

```text
Receive -> Normalize -> Analyze -> Verdict
```

## Real capture and PCAP analysis

Install Wireshark with TShark and Npcap, then list capture interfaces:

```cmd
tshark -D
```

Monitor an authorized local interface:

```cmd
python -m sentinel.server --source live --interface 1
```

Analyze a recorded PCAP without retransmitting it:

```cmd
python -m sentinel.server --source pcap --pcap "C:\NetworkData\sample.pcap"
```

Live capture may require an Administrator terminal. Only monitor networks and devices you own or are authorized to observe.

## Validate the detector

```cmd
python -m unittest discover -s tests -v
python scripts\validate.py
```

The validation script executes every labeled scenario and reports precision, recall, and a confusion matrix. Detection thresholds are configurable in `config.json`.

## Project structure

```text
sentinel/       Detection, ingestion, storage, and server modules
web/            Browser dashboard and Traffic Lab
tests/          Automated detector tests
scripts/        Validation utilities
config.json     Detection thresholds and local indicators
```

## Privacy and safety

Runtime events remain local in `data\sentiflow.db`, which is excluded from Git. Simulations create metadata records only: they do not scan hosts, transmit packets, execute malware, or replay captured payloads onto a network.

## License

MIT License. See `LICENSE`.
