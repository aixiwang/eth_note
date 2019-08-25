# -*- coding: utf-8 -*-
#============================================

import sys
import getopt
from ethereum import utils
from ethereum import transactions
import rlp
import requests
import json
import binascii

K_LONGOPT = ["key=", "to=", "value=", "tx="]
K_NODE_HOST = "https://mainnet.infura.io/ysRmvhtbbQLCx4jfjqhI"
K_NODE_PORT = "80"
K_NODE_NETWORK_ID = 1023

K_SEND_TX_STARTGAS = 90000

K_BALANCE_REQ_ID = 1
K_SEND_REQ_ID = 2
K_TX_STATUS_REQ_ID = 3
K_TX_COUNT_REQ_ID = 4
K_GAS_PRICE_REQ_ID = 5

K_ARGS_PRIV_ERROR = "Private key must be a valid 32 bytes length hex string"
K_ARGS_TO_HEX_ERROR = "Recipient address must be a valid 20 bytes hex string"
K_ARGS_VALUE__ERROR = "Value must be a valid integer number"
K_ARGS_TX_HEX_ERROR = "Transaction hash must be a valid 32 bytes length hex string"

K_DEFAULT_REQ_ERROR = "Undefined error"
K_EMPTY_ACC_REQ_ERROR = "Account was not found"
K_EMPTY_TX_REQ_ERROR = "Transaction was not found"


class RPCError(Exception):
    def __init__(self, message):
        self.message = message


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "", K_LONGOPT)
    except getopt.GetoptError:
        print(usage())
        sys.exit(2)

    if len(args) > 0:
        print(usage())
        sys.exit(2)

    priv = None
    to = None
    send_val = None
    tx = None

    for key, value in opts:
        if key == "--key":
            try:
                priv = bytes.fromhex(value)

                if len(priv) != 32:
                    print("Error: " + K_ARGS_PRIV_ERROR)
                    sys.exit(2)

            except ValueError:
                print("Error: " + K_ARGS_PRIV_ERROR)
                sys.exit(2)

        if key == "--to":
            try:
                to = bytes.fromhex(value)

                if len(to) != 20:
                    print("Error: " + K_ARGS_TO_HEX_ERROR)
                    sys.exit(2)

            except ValueError:
                print("Error: " + K_ARGS_TO_HEX_ERROR)
                sys.exit(2)

        if key == "--value":
            try:
                send_val = int(float(value)*1000000000000000000)
                print('send_val:',send_val)

                #send_val = int(value, 10)
            except ValueError:
                print("Error: " + K_ARGS_VALUE__ERROR)
                sys.exit(2)

        if key == "--tx":
            try:
                tx = bytes.fromhex(value)

                if len(tx) != 32:
                    print("Error: " + K_ARGS_TX_HEX_ERROR)
                    sys.exit(2)

            except ValueError:
                print("Error: " + K_ARGS_TX_HEX_ERROR)
                sys.exit(2)

    if priv is not None:
        if to is None and send_val is None:
            try:
                addr = utils.privtoaddr(priv)
                print('addr:',binascii.hexlify(addr))
                acc_value = get_balance(addr)
                print("Balance on \"%s\" is %s ether" % (addr.hex(), str(acc_value/utils.denoms.ether)))
            except RPCError as err:
                print("Error: " + err.message)

        elif to is not None and send_val is not None:
            try:
                tx_hash = send(priv, to, send_val)
                print("Payment of %s ether to \"%s\" scheduled" % (str(send_val/utils.denoms.ether), to.hex()))
                print("Transaction Hash: "+tx_hash)
            except RPCError as err:
                print("Exception Error from rpc service: " + err.message)
        elif to is None:
            print('\'to\' parameter must be provided to send ether')
            sys.exit(2)
        elif send_val is None:
            print('\'value\' parameter must be provided to send ether')
            sys.exit(2)
    elif tx is not None:
        try:
            to_hex, sent_val, mined = get_tx_status(tx)
            if mined:
                print("Payment of %s ether to \"%s\" confirmed" % (str(sent_val/utils.denoms.ether), to_hex[2:]))
            else:
                print("Delay in payment of %s ether to \"%s\"" % (str(sent_val / utils.denoms.ether), to_hex[2:]))
        except RPCError as err:
            print("Error: " + err.message)
    else:
        print(usage())
        sys.exit(2)


def get_balance(addr):
    addr_str = "0x" + addr.hex()
    params = [addr_str, "latest"]

    rpc_params = {"jsonrpc": "2.0", "method": "eth_getBalance", "params": params, "id": K_BALANCE_REQ_ID}

    req_json = json.dumps(rpc_params)
    response = requests.post(K_NODE_HOST+":"+K_NODE_PORT, data=req_json)

    err_message = get_req_error(response)
    if err_message is not None:
        raise RPCError(err_message)

    resp_dic = response.json()

    if resp_dic["result"] is None:
        raise RPCError(K_EMPTY_ACC_REQ_ERROR)

    return int(resp_dic["result"], 16)

#-----------------------------------
# send2
# input: priv -- hex string
#        to   -- hex string
#        send_val -- int
#        data -- hex string
#-----------------------------------    
def send2(priv,to,send_val,data=None):    
    try:
        priv_b = bytes.fromhex(priv)
        to_b = bytes.fromhex(to)
        #if data != None:
        #    data_b = bytes.fromhex(data)
        
        tx_hash = send(priv_b, to_b, send_val,data)
        print("Payment of %s ether to \"%s\" scheduled" % (str(send_val/utils.denoms.ether), to))
        print("Transaction Hash: "+tx_hash)
        return 0
    except RPCError as err:
        print("Exception Error from rpc service: " + err.message)
        return -1

        
def send(priv, to, value,data = b''):
    addr = utils.privtoaddr(priv)
    print('addr:',binascii.hexlify(addr))

    nonce = get_tx_count(addr)

    print('nonce:',str(nonce))

    gasprice = get_tx_gasprice()

    print('gasprice:',str(gasprice))

    trans = transactions.Transaction(nonce, gasprice, K_SEND_TX_STARTGAS, to, value, data)
    #trans_hex = "0x" + rlp.encode(trans.sign(priv, K_NODE_NETWORK_ID)).hex()
    trans_hex = "0x" + rlp.encode(trans.sign(priv)).hex()

    rpc_params = {"jsonrpc": "2.0", "method": "eth_sendRawTransaction", "params": [trans_hex], "id": K_SEND_REQ_ID}

    req_json = json.dumps(rpc_params)

    print('req_json:',req_json)

    response = requests.post(K_NODE_HOST + ":" + K_NODE_PORT, data=req_json)
    print('response:',str(response))

    err_message = get_req_error(response)
    print('err_message:',str(err_message))

    if err_message is not None:
        raise RPCError(err_message)

    
    resp_dic = response.json()
    print('resp_dic:',str(resp_dic))

    if resp_dic["result"] is None:
        raise RPCError(K_DEFAULT_REQ_ERROR)

    return resp_dic["result"]


def get_tx_count(addr):
    addr_str = "0x" + addr.hex()
    params = [addr_str, "latest"]

    rpc_params = {"jsonrpc": "2.0", "method": "eth_getTransactionCount", "params": params, "id": K_TX_COUNT_REQ_ID}

    req_json = json.dumps(rpc_params)
    response = requests.post(K_NODE_HOST + ":" + K_NODE_PORT, data=req_json)

    err_message = get_req_error(response)
    if err_message is not None:
        raise RPCError(err_message)

    resp_dic = response.json()

    if resp_dic["result"] is None:
        raise RPCError(K_EMPTY_ACC_REQ_ERROR)

    return int(resp_dic["result"], 16)


def get_tx_gasprice():
    rpc_params = {"jsonrpc": "2.0", "method": "eth_gasPrice", "params": [], "id": K_GAS_PRICE_REQ_ID}
    req_json = json.dumps(rpc_params)
    response = requests.post(K_NODE_HOST + ":" + K_NODE_PORT, data=req_json)

    err_message = get_req_error(response)
    if err_message is not None:
        raise RPCError(err_message)

    resp_dic = response.json()

    if resp_dic["result"] is None:
        raise RPCError(K_DEFAULT_REQ_ERROR)

    return int(resp_dic["result"], 16)


def get_tx_status(tx):
    tx_hex = "0x"+tx.hex()

    rpc_params = {"jsonrpc": "2.0", "method": "eth_getTransactionByHash", "params": [tx_hex], "id": K_TX_STATUS_REQ_ID}
    req_json = json.dumps(rpc_params)
    response = requests.post(K_NODE_HOST + ":" + K_NODE_PORT, data=req_json)

    err_message = get_req_error(response)
    if err_message is not None:
        raise RPCError(err_message)

    resp_dic = response.json()

    if resp_dic["result"] is None:
        raise RPCError(K_EMPTY_TX_REQ_ERROR)

    to_hex = resp_dic["result"]["to"]
    value = int(resp_dic["result"]["value"], 16)
    mined = resp_dic["result"]["blockNumber"] is not None

    return to_hex, value, mined


def get_req_error(resp):
    resp_dic = resp.json()

    if "error" in resp_dic:
        if "message" in resp_dic["error"]:
            return resp_dic["error"]["message"]
        else:
            return K_DEFAULT_REQ_ERROR
    else:
        return None


def usage():
    usage_str = """Usage:\n\n"""
    usage_str = usage_str + "Provides account's balance in ether\n"
    usage_str = usage_str + "\tpython3 wallet.py --key <hex private key>\n\n"
    usage_str = usage_str + "Sends value in Wei to the given account\n"
    usage_str = usage_str + """\tpython3 wallet.py --key <hex private key> --to <hex recipient address>\
 --value <wei value>\n\n"""
    usage_str = usage_str + "Provides transaction's status\n"
    usage_str = usage_str + "\tpython3 wallet.py --tx <tx hex hash>\n\n"
    usage_str = usage_str + """It is assumed that the node is running with default host ("""+K_NODE_HOST+""") \
and port ("""+K_NODE_PORT+""") and network_id="""+str(K_NODE_NETWORK_ID)+""" parameters for JSON-RPC API"""
    return usage_str

if __name__ == '__main__':
    main(sys.argv[1:])
