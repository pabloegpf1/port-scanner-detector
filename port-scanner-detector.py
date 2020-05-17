import sys
import dpkt

#Import strategies
from strategies.tcpsyn import tcpSynScan
from strategies.tcpconnect import tcpConnectScan
from strategies.tcpnull import tcpNullScan
from strategies.tcpxmas import tcpXmasScan
from strategies.tcpfin import tcpFinScan
from strategies.udp import udpScan

def main(argv):
    if(len(sys.argv)) != 2:
        print("Incorrect arguments: python3 port-scanner-detector.py <input.pcap>")
        sys.exit()
    filename = sys.argv[1]

    print("tcpSyn:",tcpSynScan(filename))
    print("tcpConnect:",tcpConnectScan(filename))
    print("tcpNull:",tcpNullScan(filename))
    print("tcpXmas:",tcpXmasScan(filename))
    print("tcpFin:",tcpFinScan(filename))
    print("udp:",udpScan(filename))

if __name__ == "__main__":
   main(sys.argv[1:])