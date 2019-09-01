__author__ = 'dk'
'''
    带内通信信道,主要实现客户端中数据包的重放流程
'''
from  Replay import  ReplayDator
from  Replay import  replay_client
from Replay import  requry_remote_port
from python_lib import  SOCKET,randomize
from config import config
import binary_op
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
        self.proto = self.stream['c2s']['meta'][0]['proto']

        #寻到的关键词
        self.keyword=[]  #{{"start":,"len":,"packet_id":,"content":,}}
        #self.keyword_db = MongoDBase(ip=config['mongodb_ip'],tablename='keyword')
    def requry_remote_port(self):
        return requry_remote_port(config['outbound_ip'],config['outbound_port'],config['outbound_create_new_channel'])
    def replay(self,replay_port=None):
        packet_id = 0
        while packet_id < len(self.stream['c2s']['meta']):
            remote_port= self.requry_remote_port()
            if replay_client(self.stream,self.replay_server_ip,remote_port,self.proto)==True:
                #原始数据包就可以直接通过,那么处理下一个client端的数据包
                packet_id +=1
            else:
                #原始数据包被拦截
                packet_index = self.stream['c2s']['meta'][packet_id]['payload_index']
                print('[%d,%d) may contain keyword'%(0,len(self.stream['c2s']['payload'][packet_index])))
                payload=self.stream['c2s']['payload'][packet_index]
                keyword_start,keyword_len = self.search_keyword(0,len(self.stream['c2s']['payload'][packet_index]),packet_id,False)
                for i in range(len(keyword_start)):
                    payload =randomize(self.stream['c2s']['payload'][packet_index],0,0)[keyword_start[i]:(keyword_start[i]+keyword_len[i])]
                    keyword={"start":keyword_start[i],"len":keyword_len[i],"packet_id":packet_id,'ansiic':binary_op.byte2ansic(payload),'hex':payload}
                    self.keyword.append(keyword)
                    print(keyword)
                    #self.keyword_db.insert(keyword)

                self.stream['c2s'][packet_id]['payload']=payload
                packet_id +=1

    def search_keyword(self,l,r,packet_id,flags=True):
        payload_index = self.stream['c2s']['meta'][packet_id]['payload_inex']
        payload = self.stream['c2s']['payload'][payload_index]
        if l+1 == r :
            return [l],[1]
        if l>=r:
            return [l],[0]
        if l<r :
            mid = int((l+r)/2)
            payload_left_modified = randomize(payload,l,mid)###修改不包含mid,是左闭右开区间[l,mid)
            payload_right_modified= randomize(payload,mid,r)###修改不包含r,是左闭右开区间[mid,r)
            sssl=[]
            sssr=[]

            #for i in range(len(payload)):
            #    sssl.append(payload[i] ^ payload_left_modified[i])
            #    sssr.append(payload[i] ^ payload_right_modified[i])
            #print(sssl)
            #print(sssr)

            #Divide into 2 sepearate branches
            self.stream['c2s']['payload'][payload_index]=payload_left_modified
            remote_port = self.requry_remote_port()

            if replay_client(self.stream,self.replay_server_ip,remote_port,self.proto) == True:
                #go through middle box,means payload left half contains keyword
                self.stream['c2s']['payload'][payload_index]=payload        #payload_right_modified
                print('[%d,%d) may contain keyword'%(l,mid))
                lkeyword_start,lkeyword_len=self.search_keyword(l,mid,packet_id)
            else:
                lkeyword_start,lkeyword_len=[l],[0]

            self.stream['c2s']['payload'][payload_index]=payload_right_modified
            remote_port = self.requry_remote_port()
            if replay_client(self.stream,self.replay_server_ip,remote_port,self.proto)==True:
                #Means payload right contains keyword
                self.stream['c2s']['payload'][payload_index]=payload        #payload_left_modified
                print('[%d,%d) may contain keyword'%(mid,r))
                rkeyword_start,rkeyword_len =self.search_keyword(mid,r,packet_id)
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
    def insert_packet(self,packet_id,packet_number=1):
        ############
        ####
        ####
        #在流的第packet_id后面插入 packet_number个随机的数据包
        #检测 策略是否和包在流的位置有关系
        ############
        pass
    def insert_payload(self,packet_id,offset,inserted_length):
        ##############
        ######
        ######
        #在流的指定数据包的指定位置,插入随机的片段.
        #检测 策略是否与keyword在包的位置有关。
        ##############
        pass
if __name__ == '__main__':
    client =Replay_Client(pcap_name=config['pcapname'],pcap_client_ip=config['pcapname_client_ip'],replay_server_ip=config['outbound_ip'])
    client.replay()
