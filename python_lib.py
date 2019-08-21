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
    stream={'s2c':[],'c2s':[]}
    for data in packets:
        src_ip = data['IP'].src
        dst_ip = data['IP'].dst
        if 'TCP' in data:
            src_port = data['TCP'].sport
            dst_port = data['TCP'].dport
            payload  = bytes(data['TCP'].payload)
            proto = 'TCP'
        elif 'UDP' in data:
            src_port = data['UDP'].sport
            dst_port = data['UDP'].dport
            payload =  bytes(data['UDP'].payload)
            proto='UDP'
        if len(payload):
            packet={'proto':proto,'id':count,'src_ip':src_ip,'dst_ip':dst_ip,'src_port':src_port,'dst_port':dst_port,'payload':payload}
            count +=1
            if src_ip==client_ip:
                packet.setdefault('direction','c2s')
                stream['c2s'].append(packet)
            elif dst_ip==client_ip:
                packet.setdefault('direction','s2c')
                stream['s2c'].append(packet)
    return stream

class SOCKET:
    def __init__(self,proto,role,ip,port):
        self.proto = proto
        self.rolo = role
        if proto=='TCP':
            self.socket = socket.socket(type=socket.SOCK_STREAM)
            if role=='server':
                self.socket.bind(('0.0.0.0',port))
                self.socket.listen(10)
                self.accept()
            if role=='client':
                self.address=(ip,port)
                self.socket.connect(self.address)
        if proto=='UDP':
            self.socket = socket.socket(type=socket.SOCK_DGRAM)
            if role=='server':
                self.socket.bind(("0.0.0.0"),port)
            if role=='client':
                self.address=(ip,port)
    def send(self,payload):
        if self.proto=='TCP':
            return  self.socket.send(payload)
        if send.proto=='UDP':
            return self.socket.sendto(payload,self.address)
    def recv(self,buffersize):
        if self.proto=='UDP':
            data,self.address=self.socket.recvfrom(buffersize)
            return data,self.address
        if self.proto=='TCP':
            data = self.socket.recv(buffersize)
            return data


if __name__ == '__main__':
    stream=extractStream('Youtube_no_retransmits.pcap',client_ip="172.20.161.222")
    print(client[-1])
    print(server[-1])