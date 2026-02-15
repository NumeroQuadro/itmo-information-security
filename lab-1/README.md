# Lab 1 Implementation: Network Security

This repository now contains a full practical implementation for:

- Nmap scanning with OS detection
- Wireshark traffic analysis
- Snort signature-based detection of scanning activity
- Ready answers for the theory questions from the assignment

## Repository Structure

- `README.md` - runbook for the lab
- `snort/local.rules` - Snort rules for scan detection
- `scripts/run_nmap_scans.sh` - reproducible Nmap traffic generator
- `scripts/test_snort_alerts.sh` - automated Snort detection test
- `answers.md` - concise answers to all additional questions

## 1. Prerequisites

Recommended environment: Kali Linux / Ubuntu VM.

Install tools:

```bash
sudo apt update
sudo apt install -y nmap wireshark snort
```

Find your network interface:

```bash
ip -br a
```

## 2. Configure Snort

Copy lab rules into Snort local rules path:

```bash
sudo cp snort/local.rules /etc/snort/rules/local.rules
```

Set your protected network in `/etc/snort/snort.conf`:

```text
ipvar HOME_NET 192.168.1.0/24
```

Make sure local rules are included in `snort.conf`:

```text
include $RULE_PATH/local.rules
```

Validate configuration:

```bash
sudo snort -T -c /etc/snort/snort.conf -i <INTERFACE>
```

## 3. Capture Traffic in Wireshark

1. Open Wireshark.
2. Start capture on `<INTERFACE>`.
3. Optional capture filter:
   - `host <TARGET_IP>`
4. Run scans from this repo (next step).
5. Use display filters to analyze probes:
   - `tcp.flags.syn == 1 && tcp.flags.ack == 0`
   - `icmp.type == 8`
   - `udp`
   - `icmp.type == 3 && icmp.code == 3`

What to report for OS detection:

- TCP probes with different flag/option combinations to open and closed ports
- ICMP Echo probes (and the host's ICMP behavior)
- UDP probes to closed ports and ICMP Port Unreachable replies
- Differences in TCP options/window/TTL used by Nmap fingerprinting

## 4. Generate Nmap Scan Traffic

Make scripts executable:

```bash
chmod +x scripts/*.sh
```

Run all required scans:

```bash
sudo scripts/run_nmap_scans.sh <TARGET_IP>
```

This script runs:

- OS detection: `-O`
- TCP SYN scan: `-sS`
- FIN scan: `-sF`
- NULL scan: `-sN`
- XMAS scan: `-sX`
- UDP scan: `-sU`

## 5. Verify Snort Detection

Automated check:

```bash
sudo scripts/test_snort_alerts.sh <INTERFACE> <TARGET_IP>
```

Expected result: alerts containing `LAB Nmap` in generated `logs_*` directory.

## 6. What Exactly to Submit

1. Command outputs for Nmap scans.
2. Wireshark screenshots/notes proving which packets were used for OS detection.
3. Snort alert logs showing scan detection.
4. Short note confirming no obvious false positives during normal traffic test.
5. Theory section from `answers.md`.

## 7. False Positive Reduction Checklist

- Keep `HOME_NET` accurate and narrow.
- Use `detection_filter` thresholds (already included in rules).
- Exclude trusted vulnerability scanner hosts if needed.
- Correlate several alerts before declaring incident.
- Tune counts/time windows to your real traffic profile.
