import dpkt
import socket
import datetime

#udp packets per second to be considered a udpScan
PACKETRATIO = 4

class Source:
    def __init__(self, ip):
        self.ip = ip
        self.udpCount = set()

def udpScan(filename):

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
        udp = ip.data

        #Check if packet is UDP
        if type(udp) != dpkt.udp.UDP:
            continue

        try:
            srcIP = socket.inet_ntoa(ip.src)
            dstIP = socket.inet_ntoa(ip.dst)+":"+str(udp.dport)
        except:
            #IP format not valid
            continue

        #Register new sources
        if(sources.get(srcIP) == None):
            sources[srcIP] = Source(srcIP)

        #Register connections to new dst
        sources[srcIP].udpCount.add(dstIP)

    delta = calculateDelta(startTime, endTime)
    return extractSuspects(sources, delta)

def extractSuspects(sources, delta):
    suspects = []
    for idx,source in enumerate(sources):
        currentSource = sources.get(source)
        connectionsPerSecond = len(currentSource.udpCount)/delta
        if(connectionsPerSecond >= PACKETRATIO):
            suspects.append({'suspect': currentSource.ip, 'reason': str("Sent "+connectionsPerSecond+" UDP packets per second")})
    return suspects

def calculateDelta(startTime, endTime):
    delta = datetime.datetime.fromtimestamp(endTime) - datetime.datetime.fromtimestamp(startTime)
    return delta.total_seconds()
