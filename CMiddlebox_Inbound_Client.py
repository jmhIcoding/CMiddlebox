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

        self.proto = self.stream['c2s'][0]['proto']

        #寻到的关键词
        self.keyword=set()  #{{"start":,"len":,"packet_id":,"content":,}}
        #self.keyword_db = MongoDBase(ip=config['mongodb_ip'],tablename='keyword')
    def requry_remote_port(self):
        rst = 0
        url = "http://%s:%s%s"%(config['outbound_ip'],config['outbound_port'],config['outbound_create_new_channel'])
        response = requests.get(url).json()
        rst = response['port']
        return rst
    def replay(self,replay_port=None):
        packet_id = 0
        while packet_id < len(self.stream['c2s']):
            remote_port=self.requry_remote_port()
            if replay_client(self.stream,self.replay_server_ip,remote_port,self.proto)==True:
                #原始数据包就可以直接通过,那么处理下一个client端的数据包
                packet_id +=1
            else:
                #原始数据包被拦截
                keyword_start,keyword_len = self.search_keyword(0,len(self.stream['c2s'][packet_id]['payload']),packet_id)
                for i in range(len(keyword_start)):
                    keyword={"start":keyword_start[i],"len":keyword_len[i],"packet_id":packet_id,"content":self.stream['c2s'][packet_id][keyword_start:(keyword_start+keyword_len)]}
                    self.keyword.add(keyword)
                    print(keyword)
                    #self.keyword_db.insert(keyword)
    def search_keyword(self,l,r,packet_id):
        payload = self.stream['c2s'][packet_id]['payload']
        if l==r:
            return l,0
        if l<r :
            mid = (l+r)/2
            payload_left_modified = randomize(payload,l,mid)
            payload_right_modified=randomize(payload,mid+1,r)

            #Divide into 2 sepearate branches
            self.stream['c2s'][packet_id]['payload']=payload_left_modified
            remote_port = self.requry_remote_port()
            if replay_client(self.stream,self.replay_server_ip,remote_port,self.proto) == False:
                #Never go through middle box,means payload left contains keyword
                lkeyword_start,lkeyword_len_=self.search_keyword(l,mid,packet_id)
            else:
                lkeyword_start,lkeyword_len=[l],[0]

            self.stream['c2s'][packet_id]['payload']=payload_right_modified
            remote_port = self.requry_remote_port()
            if replay_client(self.stream,self.replay_server_ip,remote_port,self.proto)==False:
                #Means payload right contains keyword
                rkeyword_start,rkeyword_len =self.search_keyword(mid+1,r,packet_id)
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
if __name__ == '__main__':
    client =Replay_Client(pcap_name=config['pcapname'],pcap_client_ip=config['pcapname_client_ip'],replay_server_ip=config['outbound_ip'])
    client.replay()
