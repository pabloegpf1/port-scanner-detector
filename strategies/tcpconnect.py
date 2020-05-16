import dpkt
import socket
import datetime

#Connections per second to be considered a tcpConnect scan
CONNECTIONRATIO = 100
#SYNs vs ACKs ratio to be considered as a tcpSYN scan
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

def tcpConnectScan(filename):

    pcap = dpkt.pcap.Reader(open(filename,'rb'))
    sources = {}
    startTime = 0
    endTime = 0

    for timestamp, packet in pcap:

        if(startTime == 0): 
            startTime = timestamp
        endTime = timestamp

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

    delta = calculateDelta(startTime, endTime)

    return extractSuspects(sources, delta)

def extractSuspects(sources, delta):
    suspects = []
    for idx,source in enumerate(sources):
        currentSource = sources.get(source)
        currentConnectionRatio = (currentSource.synCount + currentSource.ackCount)/delta
        #Source is suspect if it has more SYNs + ACKs than ratio
        if(currentConnectionRatio >= CONNECTIONRATIO):
            suspects.append(currentSource.ip)
            #print("SUSPECT: ", currentSource.ip, "SYNs + ACKs per second: ", currentConnectionRatio)

    return suspects

def isACK(tcp):
    return tcp.flags & dpkt.tcp.TH_ACK  != 0  

def isSYN(tcp):
    return tcp.flags & dpkt.tcp.TH_SYN  != 0

def calculateDelta(startTime, endTime):
    delta = datetime.datetime.fromtimestamp(endTime) - datetime.datetime.fromtimestamp(startTime)
    return delta.total_seconds()
