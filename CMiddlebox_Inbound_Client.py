__author__ = 'dk'
'''
    带内通信信道,主要实现客户端中数据包的重放流程
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
class Replay_Client(Replay):
    def __init__(self,pcap_name,pcap_client_ip,replay_server_ip,replay_server_start_port=None):
        super.__init__(pcap_name,pcap_client_ip)
        self.replay_server_ip = replay_server_ip    #把数据包重放到这个ip主机上
        if replay_server_start_port ==None:
            #起始端口
            self.replay_server_start_port = self.stream['c2s'][0]['dst_port']
        else:
            self.replay_server_start_port = replay_server_start_port
        self.go_through_semapher = Semaphore(value=1)
        self.keyword=set()#{{"start":,"len":,"packet_id":,"content":,}}
        self.keyword_db = MongoDBase(ip=config['mongodb_ip'],tablename='keyword')
        self.recv_set=set()

    def replay(self,replay_port=None):
        if port ==None:
            port = self.replay_server_start_port
        self.sock = SOCKET(proto=self.stream['c2s'][0]['proto'],role='client',ip=self.replay_server_ip,port=port)
        self.current_bidirection_packet_id  = 1   #目前双向通信的 packet id
        self.current_single_curse_packet_id = 0
        self.thread = Thread(target=self.recv_thread,args=(self))
        self.thread.start()
        while self.current_single_curse_packet_id < len(self.stream['c2s']):
            payload = copy.deepcopy(self.stream['c2s'][self.current_single_curse_packet_id]['payload'])
            self.sock.send(payload)
            #检查是否服务端是否收到数据包
            hash_value =hash_int(payload)
            packet_id = self.payload_hash_to_id.get(hash_value,0)
            if self.server_checker(packet_id,hash_value)==True:
                #原始数据包就可以直接通过,那么处理下一个client端的数据包
                while (packet_id +1) in self.server_packets_id and (packet_id +1) not in self.recv_set:
                    time.sleep(0.05)
                    print('wait for next packet from server...')

            else:
                #原始数据包被拦截
                keyword_start,keyword_len = self.search_keyword(0,len(payload),payload,packet_id)
                for i in range(len(keyword_start)):
                    keyword={"start":keyword_start[i],"len":keyword_len[i],"packet_id":packet_id,"content":payload[keyword_start:(keyword_start+keyword_len)]}
                    self.keyword.add(keyword)
                    self.keyword_db.insert(keyword)
            self.current_single_curse_packet_id += 1
        self.thread.join()
        self.sock.close()
    def search_keyword(self,l,r,payload,packet_id):
        if l+1==r:
            return l,1
        if l<r :
            mid = (l+r)/2
            payload_left_modified = randomize(payload,l,mid)
            self.sock.send(payload_left_modified)
            hash_value_left = hash_int(payload_modified)
            payload_right_modified=randomize(payload,mid+1,r)
            self.sock.send(payload_right_modified)
            hash_value_right = hash_int(payload_right_modified)
            #Divide into 2 sepearate branches
            if self.server_checker(packet_id,hash_value_left) == False:
                #Never go through middle box,means payload left contains keyword
                lkeyword_start,lkeyword_len_=self.search_keyword(l,mid,payload,packet_id)
            else:
                lkeyword_start,lkeyword_len=[l],[0]
            if self.search_keyword(packet_id,hash_value_right)==False:
                #Means payload right contains keyword
                rkeyword_start,rkeyword_len =self.search_keyword(mid+1,r,payload,packet_id)
            else:
                rkeyword_start,rkeyword_len=[mid+1],[0]
            #Merge 2 seperate branches
            keyword_start=[]
            keyword_end=[]
            for i in range(len(lkeyword_start)):
                if lkeyword_len[i]!=0:
                    keyword_start.append(lkeyword_start[i])
                    keyword_end.append(lkeyword_len[i]+lkeyword_start[i])
            for i in range(len(rkeyword_start)):
                if rkeyword_len[i]!=0:
                    keyword_start.append(rkeyword_start[i])
                    keyword_end.append(rkeyword_len[i]+rkeyword_start[i])
            i=0
            while True:
                if i >=len(keyword_start):
                    break
                if (i+1)<len(keyword_start) && keyword_end[i] == keyword_start[i+1] :
                    tmp=keyword_end[i+1]
                    keyword_start.remove(keyword_start[i+1])
                    keyword_end.remove(tmp)
                    keyword_end[i]=tmp
                else:
                    i=i+1
            for i in range(0,len(keyword_start)):
                keyword_end[i]=keyword_end[i]-keyword_start[i]
            return keyword_start,keyword_end
    def server_checker(self,packet_id,hash_value):
        #到达返回true
        request_url = 'http://%s:%s%s'%(config['outbound_ip'],config['outbound_port'],config['outbound_url'])
        jdata ={'packet_id':packet_id,'hash_value':hash_value}
        response = requests.post(request_url,json=jdata)
        return response.json()['result']
    def sender_thread(self):
        pass
    def recv_thread(self):
        while True:
                data = self.sock.recv(4096)
                if data:
                    #收到了重放的响应数据包
                    hash_value = hash_int(data)
                    packet_id = self.server_payload_hash_to_id.get(hash_value,0)
                    self.recv_set.add(packet_id)
                else:
                    self.sock.close()
                    break