import pyaes

def myaes_encrypt(key,in_file,out_file):
    key2 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    key2 = key + key2[len(key):]
    mode = pyaes.AESModeOfOperationCTR(key2)
    file_in = file(in_file)
    file_out = file(out_file, 'wb')
    file_out_hex = file(out_file + '.hex', 'wb')
    pyaes.encrypt_stream(mode, file_in, file_out)
    
    file_in.close()
    file_out.close()
    
    file_out = file(out_file)    
    out = file_out.read()
    out_hex = out.encode('hex')
    file_out_hex.write(out_hex)
    
    file_out_hex.close()
    file_out.close()    

    
    
    
    

def myaes_decrypt(key,in_file,out_file):
    key2 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    key2 = key + key2[len(key):]
    mode = pyaes.AESModeOfOperationCTR(key2)
    file_in = file(in_file)
    file_out = file(out_file, 'wb')
    pyaes.decrypt_stream(mode, file_in, file_out)
    file_in.close()
    file_out.close()
    
def myaes_decrypt_from_hex(key,in_file,out_file):
    key2 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    key2 = key + key2[len(key):]
    mode = pyaes.AESModeOfOperationCTR(key2)
    
    file_in_hex = file(in_file)
    din = file_in_hex.read().decode('hex')
    file_in_bin = file(in_file + '.bin', 'wb')    
    file_in_bin.write(din)
    file_in_hex.close()
    file_in_bin.close()
    
    file_in = file(in_file + '.bin')
    file_out = file(out_file, 'wb')
    pyaes.decrypt_stream(mode, file_in, file_out)
    file_in.close()
    file_out.close()    

#------------------------------------------
#        M A I N    L O O P
#------------------------------------------ 
if __name__ == '__main__':
    
    myaes_encrypt('testkey','test1.txt','test2.txt')
    myaes_decrypt('testkey','test2.txt','test3.txt')
    myaes_decrypt_from_hex('testkey','test2.txt.hex','test4.txt')