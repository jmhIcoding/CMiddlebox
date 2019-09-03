__author__ = 'jmh081701'

from pymongo import  *
import config
class MongoDBase:
    def __init__(self,ip,username="s9",pwd="123456",dbname="CMiddlebox",port="27017",tablename="tasks"):
        self.client =MongoClient("mongodb://%s:%s/%s"%(ip,port,dbname))
        self.db=self.client[dbname]
        self.table=self.db[tablename]

    def get(self,cond={}):
        rst=list()
        datas=self.table.find(cond)
        for each in datas:
            rst.append(each)
        return rst

    def insert(self,data):
        return self.table.insert(data)

    def delete(self,cond):
        return self.table.delete_many(cond)
    def update_one(self,cond,set_clause):
        return self.table.update(cond,{"$set":set_clause})
if __name__ == '__main__':
    db = MongoDBase(ip=config.config['mongodb_ip'],port=config.config['mongodb_port'],dbname=config.config['mongodb_dbname'])
    datas = db.get({})
    for each in datas:
        print(each)
    #db.delete({})
