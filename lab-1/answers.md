# Laboratory Work 1 Report: Network Security

## Objective

Study practical methods of network attack execution and traffic-based detection using `Nmap`, `Wireshark`, and `Snort`.

## Task 1 Execution Summary

1. Nmap was run with OS detection (`-O`) and TCP scanning to generate controlled attack-like traffic.
2. Captured packets were analyzed in Wireshark (`.pcap`) to identify probe patterns used for OS inference.
3. Snort was installed and configured with local signatures to detect scan behavior.
4. Detection quality was checked against real scan attempts and compared with normal traffic to evaluate false positives.

## Packets Used for OS Detection (Nmap)

Nmap OS detection relies on active TCP/IP fingerprinting. The scanner sends specific probes and evaluates reply characteristics:

- TCP probes with different flag combinations and options.
- SYN-based behavior against open and closed ports.
- ICMP/TCP response features (TTL, window size, DF bit, option order, reset behavior, timing).

The combination of these response fingerprints is matched against known OS signatures.

## Snort Signatures Used in the Lab

- `sid:1000001` - Nmap SYN scan burst (`flags:S`, threshold by source).
- `sid:1000002` - FIN scan pattern (`flags:F`).
- `sid:1000003` - NULL scan pattern (`flags:0`).
- `sid:1000004` - XMAS scan pattern (`flags:FPU`).
- `sid:1000005` - UDP scan burst pattern (`alert udp ... detection_filter`).

## Additional Questions and Answers

### 1) What is the difference between active and passive network scanning?

Active scanning sends packets to targets and analyzes responses. Passive scanning only observes existing traffic. Active scanning gives fuller visibility but is detectable; passive scanning is stealthier but depends on available traffic.

### 2) Why can Snort generate false positives? How can this be fixed?

False positives appear because of generic signatures, noisy networks, weak thresholds, and incorrect variables (for example `HOME_NET`). Fixes include rule tuning, better thresholds, suppress/whitelist for trusted sources, and alert correlation with packet captures.

### 3) What obfuscation techniques are used to hide Nmap scans?

Attackers use low-and-slow timing (`-T1`, `-T2`), packet fragmentation (`-f`), decoys (`-D`), source spoofing, randomized scan order, and stealth scan types (FIN/NULL/XMAS).

### 4) How does Wireshark work in traffic analysis?

Wireshark captures packets from an interface, decodes protocol layers, and allows filtering/reconstruction of flows. It is used to inspect headers, flags, timing, retransmissions, and payload-level protocol behavior.

### 5) What are core IDS principles?

Traffic collection, parsing/normalization, detection logic (signatures or anomalies), alerting, and analyst triage. Detection quality depends on visibility, rule quality, and environment-specific tuning.

### 6) IDS vs IPS: key differences and usage

IDS detects and alerts (out-of-band). IPS is inline and can block/drop traffic automatically. IDS is preferred for monitoring with minimal service risk; IPS is preferred when immediate prevention is required.

### 7) When is whitelisting preferable to IDS/IPS?

Whitelisting is effective in stable, predictable environments (industrial/control networks, fixed-purpose servers, critical internal APIs) where permitted behavior is narrowly defined.

### 8) What methods are used to detect port scanning?

Rate thresholds, unique-port counting per source, TCP flag pattern checks, failed-connection ratios, horizontal/vertical scan profiling, and correlation within time windows.

### 9) Signature-based vs anomaly-based detection

Signature-based detection matches known patterns and is precise for known threats, but weak against unknown attacks. Anomaly-based detection finds deviations from baseline and can catch unknown attacks, but often increases false positives.

### 10) How can false positives be reduced in Snort and other IDS?

Correct `HOME_NET` and variables, tune thresholds, disable irrelevant signatures, use suppression/allowlists where justified, segment policies by host role, and continuously validate alerts with packet-level evidence.

### 11) How does passive scanning differ from active scanning in terms of security?

Passive scanning has lower operational impact and lower detectability risk, but less coverage. Active scanning provides deeper insight but is noisy and may trigger defensive controls or service instability.

### 12) What stealth techniques does Nmap use?

Half-open SYN scanning, FIN/NULL/XMAS probing, timing reduction, fragmentation, decoys, spoofing, and source-port manipulation.

### 13) How do SYN, FIN, and NULL scans differ?

SYN scan sends SYN and infers state by SYN/ACK or RST replies. FIN scan sends FIN to observe RFC-specific behavior. NULL scan sends no TCP flags. FIN/NULL may evade simple filters but are less reliable on some stacks.

### 14) How can attacker scanning be detected and prevented?

Detect using IDS/IPS signatures, NetFlow behavior analytics, firewall logs, and scan-rate thresholds. Prevent/mitigate using segmentation, strict ACLs, rate limiting, honeypots/tarpits, hardening, and minimizing exposed services.

## Conclusion

The lab demonstrates that controlled Nmap scanning can be correlated with Snort alerts and packet-level Wireshark evidence. Accurate detection requires both correct rule logic and environment-specific tuning to reduce false positives.
