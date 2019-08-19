__author__ = 'dk'
import  scapy
from scapy.all import *
from scapy.utils import PcapReader
def extractStream(pcapfilename,client_ip):
    ####
    #每个pcap应该只含有一条流
    ####
    packets = rdpcap(pcapfilename)
    count = 1
    client_stream=[]
    server_stream=[]
    for data in packets:
        src_ip = data['IP'].src
        dst_ip = data['IP'].dst
        proto = data['IP'].proto
        if 'TCP' in data:
            src_port = data['TCP'].sport
            dst_port = data['TCP'].dport
            payload  = bytes(data['TCP'].payload)
        elif 'UDP' in data:
            src_port = data['UDP'].sport
            dst_port = data['UDP'].dport
            payload =  bytes(data['UDP'].payload)
        if len(payload):
            packet={'count':count,'src_ip':src_ip,'dst_ip':dst_ip,'src_port':src_port,'dst_port':dst_port,'payload':payload}
            count +=1
            if src_ip==client_ip:
                packet.setdefault('direction','c2s')
                client_stream.append(packet)
            elif dst_ip==client_ip:
                packet.setdefault('direction','s2c')
                server_stream.append(packet)
    return client_stream,server_stream
if __name__ == '__main__':
    client,server=extractStream('Youtube_no_retransmits.pcap',client_ip="172.20.161.222")
    print(client[-1])
    print(server[-1])