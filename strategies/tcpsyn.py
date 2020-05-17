import dpkt
import socket

#SYNs vs ACKs ratio to be considered as a scan
RSTRATIO = 100
MINSYN = 100

#Flags
ACK = 0x010
SYN = 0x002
RST = 0x004

class Source:
    def __init__(self, ip):
        self.ip = ip
        self.synCount = 0
        self.rstCount = 0
        self.ackCount = 0

    def addSyn(self):
        self.synCount += 1

    def addRst(self):
        self.rstCount += 1

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

        #Register new source
        if(sources.get(srcIP) == None):
            sources[srcIP] = Source(srcIP)

        #Count SYNs and ACKs per source
        if(tcp.flags == SYN):
            sources.get(srcIP).addSyn()
        elif(tcp.flags == RST):
            sources.get(srcIP).addRst()
        elif(tcp.flags == ACK):
            sources.get(srcIP).addAck()

    return extractSuspects(sources)

def extractSuspects(sources):
    suspects = []
    for idx,source in enumerate(sources):
        currentSource = sources.get(source)
        #Source is suspect if it has more SYNs than ACKs (depends on ratio)
        if( (currentSource.synCount > MINSYN) & (currentSource.synCount > RSTRATIO*currentSource.rstCount)):
            suspects.append(currentSource.ip)
            print("SUSPECT: ", currentSource.ip, "Sent SYNs", currentSource.synCount, "Sent RSTs", currentSource.rstCount, "Sent ACKs", currentSource.rstCount)

    return suspects