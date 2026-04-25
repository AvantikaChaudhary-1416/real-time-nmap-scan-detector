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
- Uses packet flags (SYN, ACK, FIN)
- Tracks unique ports
- Applies thresholds and scoring
- Blocks suspicious IPs

## 📁 Logs
- suspicious.log
- confirmed.log
