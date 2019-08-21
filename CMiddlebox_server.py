__author__ = 'dk'
import  python_lib
import  flask
from  flask import  Flask
import  threading
stream = python_lib.extractStream("Youtube_no_retransmits.pcap",client_ip="172.20.161.222")['s2c']
server_ids = set()
for each in stream:
    server_ids.add(each['id'])
current_id = 1
current_curse = 0

recv_ids=set()
send_ids=set()
print('begin server')
def flask_feedback():
    app=Flask(__name__)
    global recv_ids
    @app.route("/cmiddlebox",methods=['POST'])
    def feedback():
        inputJson = flask.request.json
        response = {'result':True}
        if inputJson['id'] in recv_ids:
            response['result']=True
        else:
            response['result']=False
        return  flask.jsonify(response)
    app.run(host='0.0.0.0',port=8000)
th=threading.Thread(target=flask_feedback)
th.start()

if stream[0]['proto']=='TCP':
    SOCK = python_lib.SOCKET('TCP','server','0.0.0.0',port=stream[0]['src_port'])
elif stream[0]['proto']=='UDP':
    SOCK = python_lib.SOCKET('UDP','server','0.0.0.0',port=stream[0]['src_port'])

print("running....")
while True:
    while current_id not in server_ids:
        data = SOCK.recv(4096)
        print('recv %d'%current_id)
        recv_ids.add(current_id)
        current_id +=1
    while current_id in server_ids:
        payload=stream[current_curse]['payload']
        SOCK.send(payload)
        print('send %d'%current_id)
        send_ids.add(current_id)
        current_curse =current_curse +1
        current_id +=1

