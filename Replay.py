__author__ = 'dk'
import python_lib
from hash import  hash_int
class Replay:
    def __init__(self,pcapname,pcap_client_ip):
        #pcap_client_ip 是抓取的原始pcap里面,主动向外发起请求的ip 地址,这个一般就是客户端IP
        #重放的数据流
        self.stream = python_lib.extractStream(pcapname,pcap_client_ip)
        self.client_packets_id=set()    #客户端需要发送的数据包的id号
        self.server_packets_id=set()    #服务端需要发送的数据的id号
        self.server_payload_hash_to_id={}
        self.client_payload_hash_to_id={}
        self.payload_hash_to_id={}
        for each in self.stream['c2s']:
            hash_value =hash_int(each['payload'])
            self.client_payload_hash_to_id[hash_value] = each['id']
            self.payload_hash_to_id[hash_value]=each['id']
            self.client_packets_id.add(each['id'])

        for each in self.stream['s2c']:
            hash_value = hash_int(each['payload'])
            self.server_payload_hash_to_id[hash_value]=each['id']
            self.payload_hash_to_id[hash_value]=each['id']
            self.server_packets_id.add(each['id'])
