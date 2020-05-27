# port-scanner-detector
Scan pcap files and detect IPs that might be scanning for open ports in all of the devices in a network. This program is highly modular and very simple so it is easy to add new modules that can detect other type of scans. 
The following port scanning techniques are built in:
- TcpSyn
- TcpConnect
- TcpNull
- TcpFin
- TcpXmas
- Udp

Generate a pcap file using tcpdump and pass it as an argument to the detector and it will show the suspects for each scanning technique.
You can also test the detector with the simulated traffic files inside the /examples directory.
## Setup
1. Download or clone project
2. Install dependencies: ```pip3 install -r requirements.txt```
3. Generate pcap file (tcpdump)
4. Analyze the traffic: ```python3 detector.py <path_to_pcap>```
