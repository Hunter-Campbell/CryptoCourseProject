import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from HelperMethods import *

#Server setup stuff
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 52222
socket.bind(('127.0.0.1', port))
socket.listen(1)

#This handles the communicaton loops for CBC, ECB and OFB
#Since ECB is not stateful while CBC and OFB are stateful, this function can take an optional paramater for the stateful ciphers
#The optional paramater is for a secondary decryption cipher object to go along with the main cipher object.
def communcation_loop(client, cipher, addr, *optional_decryption_cipher):
    if len(optional_decryption_cipher) <= 0:
        #While loop for communication with the client (if the server or client type "bye!" the client will disconnect and the server will wait for a new client)
        while True:
            received_cipher_text = recv_one_message(client)
            received_plain_text = decrypt_and_display(received_cipher_text, cipher)
            if received_plain_text == "bye!":
                encrypt_and_send("bye!".encode(), client, cipher)
                print(f"\nClient {addr} has disconnected")
                break

            user_message_plaintext = input("\nPlease enter a message to be encrypted and sent to the client: ")
            encrypt_and_send(user_message_plaintext.encode(), client, cipher)
    #This else block is for communication using stateful ciphers IE CBC and OFB (stateful means you cant encrypt and decrypt with the same object)
    else:
        while True:
            received_cipher_text = recv_one_message(client)
            received_plain_text = decrypt_and_display(received_cipher_text, cipher, optional_decryption_cipher[0])
            if received_plain_text == "bye!":
                encrypt_and_send("bye!".encode(), client, cipher)
                print(f"\nClient {addr} has disconnected")
                break

            user_message_plaintext = input("\nPlease enter a message to be encrypted and sent to the client: ")
            encrypt_and_send(user_message_plaintext.encode(), client, cipher)


def main():
    while True:
        #Server connection stuff
        print("Awaiting new Client")
        client, addr = socket.accept() 
        print("Client Connected")

        #The first thing that needs to be received from the client is the AES mode we will be using.
        client_AES_mode = recv_one_message(client)
        print(f"AES mode received: {client_AES_mode}")

        #Receive the key from the client this is generated once per client session which is why it is received out of a loop.
        received_key = recv_one_message(client)
        print(f"Received key from client: {received_key}")

        #Execute this IF block if the mode is ECB
        if client_AES_mode == b"ECB":
            #Create the AES object with the key
            cipher = AES.new(received_key, AES.MODE_ECB)

            communcation_loop(client, cipher, addr)

        #Execute this IF block if the mode is CCB
        elif client_AES_mode == b"CBC":
            #Receive the iv from the client.
            received_iv = recv_one_message(client)
            print(f"Received iv from client: {received_iv}")

            #CBC mode is stateful meaning the same object cannot encrypt and decrypt.  This is why we need a decryption and encryption cipher object
            enc_cipher = AES.new(received_key, AES.MODE_CBC, received_iv)
            dec_cipher = AES.new(received_key, AES.MODE_CBC, received_iv)

            communcation_loop(client, enc_cipher, addr, dec_cipher)

        elif client_AES_mode == b"OFB":
            #Receive the iv from the client.
            received_iv = recv_one_message(client)
            print(f"Received iv from client: {received_iv}")

            #OFB mode is stateful meaning the same object cannot encrypt and decrypt.  This is why we need a decryption and encryption cipher object
            enc_cipher = AES.new(received_key, AES.MODE_OFB, received_iv)
            dec_cipher = AES.new(received_key, AES.MODE_OFB, received_iv)

            communcation_loop(client, enc_cipher, addr, dec_cipher)


        else:
            print(f"Problem with reveived AES mode: {client_AES_mode}")


    

#Start execution
main()