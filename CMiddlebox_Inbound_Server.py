__author__ = 'dk'
'''
    带内通信信道,主要实现服务端中数据包的重放流程
'''
from  Replay import Replay
from python_lib import  SOCKET,randomize
from hash import  hash_int
from  threading import  Semaphore
import  copy
from dbtool import MongoDBase
from config import config
import  requests
import time
from  threading import  Thread
class Replay_Server(Replay):
    def __init__(self,pcap_name,pcap_client_ip,replay_server_start_port=None):
        super(Replay_Server,self).__init__(pcap_name,pcap_client_ip)
        if replay_server_start_port ==None:
            #起始端口
            self.replay_server_start_port = self.stream['c2s'][0]['dst_port']
        else:
            self.replay_server_start_port = replay_server_start_port
        self.go_through_semapher = Semaphore(value=1)
        self.recv_db = MongoDBase(ip=config['mongodb_ip'])
        self.recv_set=set()
    def replay(self,port=None):
        if port ==None:
            port = self.replay_server_start_port
        self.sock = SOCKET(proto=self.stream['s2c'][0]['proto'],role='server',ip="0.0.0.0",port=port)
        self.current_packet_id = -1
        self.th_recv = Thread(target=self.recv_thread)
        self.th_send = Thread(target=self.send_thread)
        self.th_recv.start()
        self.th_send.start()
        self.th_recv.join()
        #self.th_send.join()
    def send_thread(self):
        while True:
            if self.current_packet_id + 1 in self.server_packets_id:
                payload = self.stream['payload'][self.current_packet_id+1-1]
                self.sock.send(payload)
                self.current_packet_id +=1
                print('send {packet_id:%d,hash:%d}'%(self.current_packet_id,hash_int(payload)))
                time.sleep(0.02)
    def recv_thread(self):
        while True:
            data = self.sock.recv(4096)
            if data:
                hash_value = hash_int(data)
                packet_id = self.payload_hash_to_id.get(hash_value,-1)
                print('recv {id:%d,hash:%d}'%(packet_id,hash_value))
                if packet_id > 0:
                    self.current_packet_id = packet_id
                    self.recv_db.insert({'packet_id':packet_id,'hash_value':hash_value})
            else:
                self.sock.close()
                break
if __name__ == '__main__':
    server = Replay_Server(pcap_name='Youtube_no_retransmits.pcap',pcap_client_ip="172.20.161.222")
    server.replay()
