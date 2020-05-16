import dpkt
import socket

SYNACKRATIO = 3

def tcpSynScan(pcap):

    sources = {}

    for timestamp, packet in pcap:

        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        tcp = ip.data

        #Check if packet is TCP
        if type(tcp) != dpkt.tcp.TCP:
            continue

        srcIP = socket.inet_ntoa(ip.src)

        #Register new sources
        if(sources.get(srcIP) == None):
            sources[srcIP] = Source(srcIP)

        #Count SYNs and ACKs per source
        if(isSYN(tcp)):
            sources.get(srcIP).addSyn()
        elif(isACK(tcp)):
            sources.get(srcIP).addAck()

    return extractSuspects(sources)

def extractSuspects(sources):
    suspects = []
    for idx,source in enumerate(sources):
        currentSource = sources.get(source)
        #Source is suspect if it has more SYNs than ACKs (depends on ratio)
        if(currentSource.synCount >= SYNACKRATIO*currentSource.ackCount):
            suspects.append(currentSource.ip)
            #print("SUSPECT: ", currentSource.ip, "SYNs: ", currentSource.synCount, "ACKs: ", currentSource.ackCount)

    return suspects

class Source:
    def __init__(self, ip):
        self.ip = ip
        self.synCount = 0
        self.ackCount = 0
    
    def addSyn(self):
        self.synCount += 1
    
    def addAck(self):
        self.ackCount += 1

def isACK(tcp):
    return tcp.flags & dpkt.tcp.TH_ACK  != 0  

def isSYN(tcp):
    return tcp.flags & dpkt.tcp.TH_SYN  != 0
