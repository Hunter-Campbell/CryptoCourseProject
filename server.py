import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import struct

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 52222
socket.bind(('127.0.0.1', port))
socket.listen(1)

#Send message to client (can be string or bytes)
def send_message(client, message):
    if(isinstance(message, str)):
        client.send(message.encode())
    else:
        client.send(message)


#Receive message from client (can be string or bytes).  If message is greater than the buffer, loop to receive all data
# def receive_message(client):
#     received_msg = client.recv(1024) 

#     if(isinstance(received_msg, str)):
#         complete_msg=''
#         while True:
        
#             complete_msg += received_msg.decode()
#             if len(received_msg) <= 1024:
#                 break
#             received_msg = client.recv(1024) 

#         print(complete_msg)
#         return complete_msg
    
#     else:
#         return received_msg

def recv_one_message(client):
    lengthbuf = recvall(client, 4)
    length, = struct.unpack('!I', lengthbuf)
    return recvall(client, length)

def recvall(server, count):
    buf = b''
    while count:
        newbuf = server.recv(count)
        if not newbuf: return None
        buf += newbuf
        count -= len(newbuf)
    return buf

#Main program execution
def main():

    print("Waiting for Client")
    client, addr = socket.accept() 
    print("Client Connected")

    #The first thing that needs to be received from the client is the AES mode we will be using.  This receive_message is for that
    client_AES_mode = recv_one_message(client)
    print(client_AES_mode)
    if client_AES_mode == b"ECB":
        print("I have recognized ECB")
        received_key = recv_one_message(client)
        print(f"Received key from client: {received_key}")

    














    # cipher = AES.new(received_key, AES.MODE_ECB)

    # msg = cipher.encrypt(b"Hello")

    # print(msg)

    # decrypt = cipher.decrypt(msg)

    # print(decrypt)

    # while True:
    #     print("Waiting for Client")
    #     client, addr = socket.accept() 
    #     print("Client Connected")

        # current_client_disconnected = False
        # while current_client_disconnected == False:                   
        #     received_msg = receive_message(client)
        #     if received_msg == "bye!":
        #         current_client_disconnected = True
        #     send_message(client, received_msg)
        #     print(received_msg)

#Start execution
main()