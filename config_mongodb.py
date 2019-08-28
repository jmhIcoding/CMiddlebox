#coding:utf-8
__author__ = 'jmh081701'
#注意,本文件夹用于设置mongodb的属性,重新设置后,需要重启整个服务
import os
import sys
import pymongo
sys.path.append(os.path.realpath("../"))


from  taskmanager.dbtool import  MongoDBase
from  taskmanager.config import config
import  json
mongoclient = MongoDBase(username=config['mongodb_username'],
                     pwd=config['mongodb_pwd'],
                     ip=config['mongodb_ip'],
                     dbname=config['mongodb_dbname'],
                     port=config['mongodb_port'],
                     tablename=config['mongodb_table'])
if os.path.exists(config["runing_result_file_"]):
    with open(config["runing_result_file_"],"r") as fp:
        runing_result = json.load(fp)
else:
    runing_result={}
if ("SetExpireTime" not in runing_result ) or ("SetExpireTime" in runing_result and runing_result["SetExpireTime"]==False):
    mongoclient.table.create_index([("timestamp",pymongo.ASCENDING)],expireAfterSeconds=config["mongodb_expireTime"])
    runing_result["SetExpireTime"]=True
    print("SetExpireTime Well")
else:
    mongoclient.db.command({"collMod":config['mongodb_table'],"index":{"keyPattern":{"timestamp":pymongo.ASCENDING},"expireAfterSeconds":config["mongodb_expireTime"]}})
    runing_result["SetExpireTime"]=True

with open(config["runing_result_file_"],"w") as fp:
    json.dump(runing_result,fp)
