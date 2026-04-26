# Real-Time Nmap Scan Detector

## 📌 Overview
This project is a real-time Network Intrusion Detection System (IDS) that detects Nmap scans and network attacks using packet analysis.

## 🚀 Features
- Detects SYN scans and SYN floods
- Detects TCP port scans
- Detects FIN, NULL, XMAS scans
- Detects UDP and ICMP floods
- Uses scoring-based detection system
- Uses short-term and long-term time windows

## ⚙️ Technologies Used
- Python
- Scapy
- Networking concepts (TCP/IP)

## ▶️ How to Run
1. Install dependencies:
   pip install scapy

2. Run the script:
   python ids.py

## 📊 Detection Logic
The detector uses a **dual time-window architecture**:
- **Fast window (5s):** catches aggressive, high-rate scans
- **Slow window (60s):** catches evasive scans that spread packets 
  over time to avoid threshold-based detection

For each source IP, it tracks:
- SYN/ACK ratio (high SYN with no ACK = scan behavior)
- Outgoing RST rate (closed port responses)
- Unique destination ports contacted
- Packet rate over both windows

Alerts are scored and cross-validated across both windows before 
being confirmed — reducing false positives.

## 📁 Logs
- suspicious.log
- confirmed.log
