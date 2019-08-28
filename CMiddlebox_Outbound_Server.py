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
app=Flask(__name__)
mongodb = MongoDBase(ip=config['mongodb_ip'])
@app.route(rule=config['outbound_url'],methods=['POST'])
def outbound_checker():
    inputJson = flask.request.json
    response = {'result':True}
    filter=mongodb.get(cond=inputJson)
    if filter==None:
        response['result']=False
    return flask.jsonify(response)
app.run(host='0.0.0.0',port=config['outbound_port'])

