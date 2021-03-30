import socket
import time
import threading
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

server=socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1",9999))
server.listen(10)

public_key=[]
all_connections=[]

key = RSA.generate(3072)
private_key,public = key, key.publickey()
rsa_private_key = PKCS1_OAEP.new(private_key)
def recieve_keys(client):
    pub = RSA.importKey(client.recv(2048), passphrase=None)
    public_key.append(pub)
    print('public key is recieved')
    try:
            while(True):
                l1=[]
                l2=[]
                mess=client.recv(2048)
                if(len(mess)):
                    client2=all_connections[all_connections.index(client)-1]
                    decrypted_text1 = rsa_private_key.decrypt(mess).decode()
                    l1.append(decrypted_text1)
                    print(decrypted_text1)
                    modify_and_send_message(client2)
                mess=client2.recv(2048)
                if(len(mess)):  
                    decrypted_text2 = rsa_private_key.decrypt(mess).decode()
                    l2.append(decrypted_text2)
                    modify_and_send_message(client)
                if(len(l1)==2):
                    print('Original message sent by client1 :{}'.format(l1[0]+l1[1]))
                    del l1
                if(len(l2)==2):
                    print('Original message sent by client2 :{}'.format(l2[0]+l2[1]))
                    del l2
    except:
            exit            

def send_keys(client,add):
    client.send(public.exportKey(format='PEM', passphrase=None, pkcs=1))
    recieve_keys(client)
    
def modify_and_send_message(client):
    false_message=input('enter the false message u want to send:   ').encode()
    rsa_key =public_key[all_connections.index(client)]
    rsa_public_key = PKCS1_OAEP.new(rsa_key)
    encrypted_text = rsa_public_key.encrypt(false_message)
    client.send(encrypted_text)   
    

while True:
        conn, address = server.accept()
        all_connections.append(conn)
        print('connection has been established with : {}'.format(address))
        thread = threading.Thread(target=send_keys, args=(conn,address)).start()
