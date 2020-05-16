import sys
import dpkt

#Import strategies
from strategies.tcpsyn import tcpSynScan
from strategies.tcpconnect import tcpConnectScan
from strategies.tcpnull import tcpNullScan
from strategies.tcpxmas import tcpXmasScan
from strategies.tcpfin import tcpFinScan

def main(argv):
    if(len(sys.argv)) != 2:
        print("Incorrect arguments: python3 port-scanner-detector.py <input.pcap>")
        sys.exit()
    filename = sys.argv[1]

    print("tcpSyn:",tcpSynScan(filename))
    print("tcpConnect:",tcpConnectScan(filename))
    print("tcpNull:",tcpNullScan(filename))
    print("tcpxmas:",tcpXmasScan(filename))
    print("tcpfin:",tcpFinScan(filename))

if __name__ == "__main__":
   main(sys.argv[1:])