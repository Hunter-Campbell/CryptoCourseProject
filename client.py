import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import sys
import struct

aes_valid_modes = ["ECB", "CBC", "OFB"]
valid_key_lengths = [128, 192, 256]
args = sys.argv

#Check if the proper number of command line arguments was used
if len(args) == 3:

    #Catch any value errors from the command line 
    try:

        #Make sure given key is in the valid keys list.  Stop program execution if invalid
        if int(args[1]) not in valid_key_lengths:   
            print(f"Given key length is invalid.  Valid options are {valid_key_lengths}")
            sys.exit()

        #Make sure given mode is in the valid modes list.  Stop program execution if invalid
        elif args[2] not in aes_valid_modes :       
            print(f"Given AES mode is not accepted. Valid options are {aes_valid_modes}")
            sys.exit()

    #If value error occurs, notify user.  Stop program execution 
    except ValueError:
        print(f"Given value for key was not correct.  Valid options are {valid_key_lengths}")
        sys.exit()

#If arguments length is invalid, notify the user.  Stop program execution       
else:
    print(f"Incorrect argument length.  Command line format is : python client.py <keysize> <AES mode>")
    sys.exit()


#Receive message from server (can be string or bytes).  If message is greater than the buffer, loop to receive all data
def receive_message(server):
    received_msg = server.recv(1024) 
    if(isinstance(received_msg, str)):
        print("Recv String")
        complete_msg=''
        while True:
        
            complete_msg += received_msg.decode()
            if len(received_msg) <= 1024:
                break
            received_msg = server.recv(1024) 

        print(complete_msg)
        return complete_msg
    
    else:
        print("Recv Bytes")
        return received_msg.decode()

def send_one_message(server, message):
    if(isinstance(message, str)):
        length = len(message)
        server.sendall(struct.pack('!I', length))
        server.sendall(message.encode())
    else:
        print(f"I am here with {message}")
        length = len(message)
        server.sendall(struct.pack('!I', length))
        server.sendall(message)

#Send message to server
# def send_message(server, message):

#     if(isinstance(message, str)):
#         server.send(message.encode())
#         print("Sending String")
#     else:
#         server.send(len(message))
#         print("Sending Bytes")



def main():
    server = socket.socket()             
    port = 52222      
    server.connect(('127.0.0.1', port))  

    #The first thing that needs to be sent to the server is the AES mode we will be using.  This send_message is for that
    send_one_message(server, args[2])
    
    if args[2] == "ECB":
        user_key_length = int(args[1])
        #Generate a key with the given bit length converted to byte length
        key = get_random_bytes(int(user_key_length / 8))
        send_one_message(server, key)




main()
print("Client shut down")