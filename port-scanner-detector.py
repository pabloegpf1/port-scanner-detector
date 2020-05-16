import sys
import dpkt
from strategies.tcpsyn import tcpSynScan
from strategies.tcpconnect import tcpConnectScan

def main(argv):
    if(len(sys.argv)) != 2:
        print("Incorrect arguments: python3 port-scanner-detector.py <input.pcap>")
        sys.exit()
    filename = sys.argv[1]


    print("tcpSyn:",tcpSynScan(filename))
    print("tcpConnect:",tcpConnectScan(filename))


if __name__ == "__main__":
   main(sys.argv[1:])