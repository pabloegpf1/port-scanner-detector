#! /usr/bin/env python3

import sys
import dpkt
from prettytable import PrettyTable

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

    printResults("tcpSyn",tcpSynScan(filename))
    printResults("tcpConnect",tcpConnectScan(filename))
    printResults("tcpNull",tcpNullScan(filename))
    printResults("tcpXmas",tcpXmasScan(filename))
    printResults("tcpFin",tcpFinScan(filename))
    printResults("udp",udpScan(filename))

def printResults(strategyName, results):
    
    print("\n-----||",strategyName,"||-----\n")

    if(len(results) == 0):
        print("No port scans detected\n")
        return

    table = PrettyTable()
    table.field_names = ["Suspect source", "Reason"]

    for idx,result in enumerate(results):
        table.add_row([result['suspect'],result['reason']])

    print(table.get_string(title=strategyName)+"\n")

if __name__ == "__main__":
  main(sys.argv[1:])
