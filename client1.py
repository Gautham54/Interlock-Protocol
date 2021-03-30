import socket
import threading
from threading import *
from Crypto.PublicKey import RSA
import pickle
from Crypto.Cipher import PKCS1_OAEP

client=socket.socket()
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


client.connect(("127.0.0.1",9999))
key = RSA.generate(3072)
private_key, public = key, key.publickey()

def INTERLOCK(con):
    while True:
       rsa_public_key = RSA.importKey(con.recv(2048), passphrase=None)
       con.send(key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))
       print("write your meassage")
       k=input()
       if(k=='bye'):
           rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
           encrypted_text = rsa_public_key.encrypt(k.encode())
           con.send(encrypted_text)
           exit()
       f=k[:len(k)//2].encode()
       s=k[len(k)//2:].encode()
       rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
       encrypted_text = rsa_public_key.encrypt(f)
       con.send(encrypted_text)
       cipher=con.recv(2048)
       if(len(cipher)):
         rsa_private_key = PKCS1_OAEP.new(private_key)
         decrypted_text1 = rsa_private_key.decrypt(cipher)
         if (decrypted_text1.decode() == 'bye'):
             print('connection is going to close')
             exit()
         print("First half of the message is recieved")
         enc=rsa_public_key.encrypt(s)
         con.send(enc)
         cipher=con.recv(2048)
         rsa_private_key = PKCS1_OAEP.new(private_key)
         decrypted_text2 = rsa_private_key.decrypt(cipher)
         decrypted_text1 = decrypted_text1.decode()
         decrypted_text2 = decrypted_text2.decode()
         print("Final message:{}".format(decrypted_text1+decrypted_text2))
         print("-----------------------------------")
       else:
         client.close()
INTERLOCK(client)