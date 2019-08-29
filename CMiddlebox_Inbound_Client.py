__author__ = 'dk'
'''
    带内通信信道,主要实现客户端中数据包的重放流程
'''
from  Replay import  ReplayDator
from  Replay import  replay_client
from python_lib import  SOCKET,randomize
from hash import  hash_int
from  threading import  Semaphore
import  copy
from dbtool import MongoDBase
from config import config
import  requests
import time
import  struct
from  threading import  Thread
class Replay_Client(ReplayDator):
    def __init__(self,pcap_name,pcap_client_ip,replay_server_ip=None,replay_server_start_port=None,inbound_port=None):
        '''
        :param pcap_name:       待重放的pcap 文件名
        :param pcap_client_ip:  pcap文件里面的客户端ip
        :param replay_server_start_port: 重放的起始端口
        :param inbound_port:
        :return:
        '''
        super(Replay_Client,self).__init__(pcap_name,pcap_client_ip)
        if replay_server_ip==None:
        #重放的目标ip
            self.replay_server_ip = config['outbound_ip']    #把数据包重放到这个ip主机上
        else:
            self.replay_server_ip = replay_server_ip

        if replay_server_start_port == None:
        #重放的起始端口
            self.replay_server_start_port = self.stream['c2s'][0]['dst_port']
        else:
            self.replay_server_start_port = replay_server_start_port
        self.go_through_semapher = Semaphore(value=1)

        #寻到的关键词
        self.keyword=set()  #{{"start":,"len":,"packet_id":,"content":,}}
        self.keyword_db = MongoDBase(ip=config['mongodb_ip'],tablename='keyword')
    def requry_remote_port(self):
        rst = self.replay_server_start_port

        return rst
    def replay(self,replay_port=None):
        while self.current_single_curse_packet_id < len(self.stream['c2s']):
            remote_port=self.requry_remote_port()
            if replay_client(self.stream,self.replay_server_ip,remote_port,)==True:
                #原始数据包就可以直接通过,那么处理下一个client端的数据包
                self.current_single_curse_packet_id +=1
            else:
                #原始数据包被拦截
                keyword_start,keyword_len = self.search_keyword(0,len(payload),payload,packet_id)
                for i in range(len(keyword_start)):
                    keyword={"start":keyword_start[i],"len":keyword_len[i],"packet_id":packet_id,"content":payload[keyword_start:(keyword_start+keyword_len)]}
                    self.keyword.add(keyword)
                    self.keyword_db.insert(keyword)
            self.current_single_curse_packet_id += 1
        self.sock.close()
        #self.thread.join()
    def search_keyword(self,l,r,payload,packet_id):
        if l==r:
            return l,0
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
                if (i+1)<len(keyword_start) and keyword_end[i] == keyword_start[i+1] :
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
                #data = self.sock.recv(min(1460,len(self.stream['s2c'][self.request_packet_id]['payload'])))
                data = self.sock.recv(len(self.stream['payload'][self.request_packet_id]))
                if data:
                    #收到了重放的响应数据包
                    hash_value = hash_int(data)
                    packet_id = self.server_payload_hash_to_id.get(hash_value,0)
                    if packet_id > 0:
                        self.recv_set.add(packet_id)
                        print('client recv: {id:%d,hash:%d}'%(packet_id,hash_value))
                else:
                    self.sock.close()
                    break
if __name__ == '__main__':
    client =Replay_Client(pcap_name='Youtube_no_retransmits.pcap',pcap_client_ip="172.20.161.222",replay_server_ip=config['outbound_ip'])
    client.replay()
