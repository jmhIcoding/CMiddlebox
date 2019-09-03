__author__ = 'dk'
'''
    带外通信信道,主要实现服务端中元数据的交互;
    即:指示那些数据包已经由客户端重放,那些数据包被服务器接受到;响应客户端的包可达性询问
    数据保存在MongoDB中
'''
from config import  config
import  flask
from  flask import  Flask
from dbtool import MongoDBase
import  Replay
import  random
import  threading
import multiprocessing
from CMiddlebox_Inbound_Server import Replay_Server
app=Flask(__name__)
#mongodb = MongoDBase(ip=config['mongodb_ip'])

replay_server =Replay_Server(config['pcapname'],config['pcapname_client_ip'])

global_inbound_process=[]
@app.route(rule=config['outbound_create_new_channel'],methods=['GET'])
def outbound_create_nchannel():
    port = 0
    while True:
        port = random.randint(11000,65530)
        if Replay.is_port_used("0.0.0.0",port,replay_server.proto)==False:
            print(port,replay_server.proto)
            break
    response={'port':port}
    for each in global_inbound_process:
        try:
            each.close()
        except:
            pass
    global_inbound_process.clear()
    th = multiprocessing.Process(target=Replay.replay_server,args=(replay_server.stream,"0.0.0.0",port,))
    th.start()
    global_inbound_process.append(th)
    print(response)
    return flask.jsonify(response)
app.run(host='0.0.0.0',port=config['outbound_port'])

