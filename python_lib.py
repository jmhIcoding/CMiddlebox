__author__ = 'dk'
import  scapy
from scapy.all import *
from scapy.utils import PcapReader
def extractStream(pcapfilename):
    ####
    #每个pcap应该只含有一条流
    ####
    packets = rdpcap(pcapfilename)
    count = 1
    for data in packets:
        src_ip = data['IP'].src
        dst_ip = data['IP'].dst
        proto = data['IP'].proto
        if 'TCP' in data:
            src_port = data['TCP'].sport
            dst_port = data['TCP'].dport
            payload  = data['TCP'].payload
        elif 'UDP' in data:
            src_port = data['UDP'].sport
            dst_port = data['UDP'].dport
            payload =  data['UDP'].payload
        packet={'count':count,'src_ip':src_ip,'dst_ip':dst_ip,'src_port':src_port,'dst_port':dst_port,'payload':payload}
        count +=1
        print(packet)

if __name__ == '__main__':
    extractStream('Youtube_no_retransmits.pcap')