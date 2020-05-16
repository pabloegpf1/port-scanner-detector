import dpkt
import socket

#SYNs vs ACKs ratio to be considered as a scan
SYNACKRATIO = 3

class Source:
    def __init__(self, ip):
        self.ip = ip
        self.synCount = 0
        self.ackCount = 0
    
    def addSyn(self):
        self.synCount += 1
    
    def addAck(self):
        self.ackCount += 1

def tcpSynScan(filename):

    pcap = dpkt.pcap.Reader(open(filename,'rb'))
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

    return suspects

def isACK(tcp):
    return tcp.flags & dpkt.tcp.TH_ACK  != 0  

def isSYN(tcp):
    return tcp.flags & dpkt.tcp.TH_SYN  != 0
