import sys
import dpkt
from strategies.tcpsyn import tcpSynScan

def main(argv):
    if(len(sys.argv)) != 2:
        print("Incorrect arguments: python3 port-scanner-detector.py <input.pcap>")
        sys.exit()
    filename = sys.argv[1]

    pcap = dpkt.pcap.Reader(open(filename,'rb'))

    print(tcpSynScan(pcap))


if __name__ == "__main__":
   main(sys.argv[1:])