import dpkt
import socket

class Source:
    def __init__(self, ip):
        self.ip = ip

def tcpFinScan(filename):

    pcap = dpkt.pcap.Reader(open(filename,'rb'))
    sources = {}
    startTime = 0
    endTime = 0

    for timestamp, packet in pcap:

        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        tcp = ip.data

        #Check if packet is TCP
        if type(tcp) != dpkt.tcp.TCP:
            continue

        srcIP = socket.inet_ntoa(ip.src)
        
        #Select TCP packets with only Fin flag
        if(isFin(tcp)):
            sources[srcIP] = Source(srcIP)

    return extractSuspects(sources)

def extractSuspects(sources):
    suspects = []
    for idx,source in enumerate(sources):
        currentSource = sources.get(source)
        suspects.append(currentSource.ip)

    return suspects

def isFin(tcp):
    return tcp.flags == 1 #FIN flag only