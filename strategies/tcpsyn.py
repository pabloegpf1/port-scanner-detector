import dpkt
import socket
import datetime

#Flags
ACK = 0x010
SYN = 0x002
SYNACK = 0x012

#Connections per second to be considered a tcpSyn scan
VALID_HANDSHAKE_RATIO = 0.1

class Source:
    def __init__(self, ip):
        self.ip = ip
        self.synCount = 0
        self.ackCount = 0
        self.synAckCount = 0

def tcpSynScan(filename):

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
        dstIP = socket.inet_ntoa(ip.dst)

        #Register new sources
        if(sources.get(srcIP) == None):
            sources[srcIP] = Source(srcIP)
        
        #Register new sources
        if(sources.get(dstIP) == None):
            sources[dstIP] = Source(dstIP)

        #Count SYNs and ACKs per source
        if(tcp.flags == SYN):
            sources.get(srcIP).synCount += 1
        elif(tcp.flags == ACK):
            sources.get(srcIP).ackCount += 1
        elif(tcp.flags == SYNACK):
            sources.get(dstIP).synAckCount += 1

    return extractSuspects(sources)

def extractSuspects(sources):
    suspects = []
    for idx,source in enumerate(sources):
        currentSource = sources.get(source)
        if(currentSource.synAckCount <= 0): continue
        print(currentSource.ackCount/currentSource.synAckCount, currentSource.ackCount, currentSource.synAckCount)
        if(currentSource.ackCount/currentSource.synAckCount < VALID_HANDSHAKE_RATIO):
            suspects.append({'suspect': currentSource.ip, 'reason': "Did not complete "+str(currentSource.synAckCount-currentSource.ackCount)+" HandShakes"})
    return suspects