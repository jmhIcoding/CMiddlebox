__author__ = 'dk'
'''
    带内通信信道,主要实现服务端中数据包的重放流程
'''
from  Replay import ReplayDator
from python_lib import  SOCKET,randomize
from hash import  hash_int
from  threading import  Semaphore
import  copy
from dbtool import MongoDBase
from config import config
import  requests
import  socket
import time
import  struct
from  threading import  Thread
class Replay_Server(ReplayDator):
    def __init__(self,pcap_name,pcap_client_ip):
        super(Replay_Server,self).__init__(pcap_name,pcap_client_ip)
        self.proto = self.stream['s2c'][0]['proto']

if __name__ == '__main__':
    server = Replay_Server(pcap_name='Youtube_no_retransmits.pcap',pcap_client_ip="172.20.161.222")
    server.replay()
