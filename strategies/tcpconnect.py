import dpkt
import socket
import datetime

#Flags
RSTACK = 0x014
SYN = 0x002

#Connections per second to be considered a tcpConnect scan
ACKRATIO = 100

class Source:
    def __init__(self, ip):
        self.ip = ip
        self.synCount = 0
        self.rstAckCount = 0

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
        if(tcp.flags == SYN):
            sources.get(srcIP).synCount += 1
        elif(tcp.flags == RSTACK):
            sources.get(srcIP).rstAckCount += 1

    delta = calculateDelta(startTime, endTime)

    return extractSuspects(sources, delta)

def extractSuspects(sources, delta):
    suspects = []
    for idx,source in enumerate(sources):
        currentSource = sources.get(source)
        #Source is suspect if it has more SYNs than RSTACKs (using ratio)
        if( (currentSource.rstAckCount > 0) & (currentSource.synCount > ACKRATIO*currentSource.rstAckCount)):
            suspects.append({'suspect': currentSource.ip, 'reason': "Sent "+str(currentSource.synCount)+" SYNs and "+str(currentSource.rstAckCount)+" RST/ACKs"})
    return suspects

def calculateDelta(startTime, endTime):
    delta = datetime.datetime.fromtimestamp(endTime) - datetime.datetime.fromtimestamp(startTime)
    return delta.total_seconds()
