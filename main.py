# -*- coding: utf-8 -*-
#============================================
import time,os,sys
import wallet
import json


#-------------------
# readfile
#-------------------
def readfile(filename):
    f = open(filename,'rb')
    fs = f.read()
    f.close()
    fs_str = fs.decode('utf-8')
    return fs_str
    

if __name__ == '__main__':

    while True:
        try:
                value = 1
                config_json_s = readfile('config.json')
                config_json = json.loads(config_json_s)
                #print('config_json:',config_json)

                to = config_json['to']
                priv = config_json['private_key']

                print('----------------------------------------------------------------------')
                s = input('input log content:\r\n')
                try:
                    s2 = s.encode('utf-8')
                except:
                    s2 = s.decode('gbk')
 
                
                retcode = wallet.send2(priv,to,value,s2)
                print('retcode:',retcode)
        except Exception as e:
            print('exception',str(e))
        
