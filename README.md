# Basic Network Sniffer in Python

## Project Overview
This project involved creating a basic network sniffer using Python and Scapy to capture and analyze network traffic. It provided hands-on experience with network packet structures and an understanding of how data flows across a network, crucial for network security.

## Technologies Used
- **Programming Language**: Python
- **Libraries**: Scapy

## Setup & Installation
1. Install Python and Scapy:
   ```bash
   pip install scapy
   ```
2. Clone this repository:
   ```bash
   git clone <repository-url>
   ```
3. Run the network sniffer script with appropriate permissions:
   ```bash
   sudo python3 sniffer.py
   ```

## Key Features
- **Packet Capture**: Captures network packets in real-time.
- **Packet Analysis**: Analyzes packet details like source and destination IP, ports, and protocols.

## Usage & Examples
Run the script and monitor the output to view live packet data:
```bash
sudo python3 sniffer.py
```

Example output:
```
Packet captured: Source IP: 192.168.1.5, Destination IP: 192.168.1.10, Protocol: TCP
```

## Learnings & Challenges
This project deepened my understanding of packet structures and network data flows, and highlighted the complexities of real-time data analysis. A challenge was handling large volumes of data without performance drops.

---


