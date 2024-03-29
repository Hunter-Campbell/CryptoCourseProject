import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from HelperMethods import *
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

"""
Names: Hunter Campbell, Carlos Nieves
Description: Client Server program for secret communication.  Makes use of RSA public keys to share an AES private key for communication
"""

#Server setup stuff
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 52222
socket.bind(('127.0.0.1', port))
socket.listen(1)

#This handles the communicaton loops for CBC, ECB and OFB
#Since ECB is not stateful while CBC and OFB are stateful, this function can take an optional paramater for the stateful ciphers
#The optional paramater is for a secondary decryption cipher object to go along with the main cipher object.
def communcation_loop(client, cipher, addr, private_key, *optional_decryption_cipher):
    if len(optional_decryption_cipher) <= 0:
        #While loop for communication with the client (if the server or client type "bye!" the client will disconnect and the server will wait for a new client)
        while True:
            received_cipher_text = recv_one_message(client)
            received_plain_text = decrypt_and_display(received_cipher_text, cipher)
            if received_plain_text == "bye!":
                encrypt_and_send("bye!".encode(), client, cipher)
                print(f"\nClient {addr} has disconnected")
                break
            
            #Send message and signature to client
            user_message_plaintext = input("\nPlease enter a message to be encrypted and sent to the client: ")
            encrypt_and_send(user_message_plaintext.encode(), client, cipher)
            send_one_message(client, get_message_signature(user_message_plaintext, private_key))
    #This else block is for communication using stateful ciphers IE CBC and OFB (stateful means you cant encrypt and decrypt with the same object)
    else:
        while True:
            received_cipher_text = recv_one_message(client)
            received_plain_text = decrypt_and_display(received_cipher_text, cipher, optional_decryption_cipher[0])
            if received_plain_text == "bye!":
                encrypt_and_send("bye!".encode(), client, cipher)
                print(f"\nClient {addr} has disconnected")
                break
            
            #Send message and signature to client
            user_message_plaintext = input("\nPlease enter a message to be encrypted and sent to the client: ")
            encrypt_and_send(user_message_plaintext.encode(), client, cipher)
            send_one_message(client, get_message_signature(user_message_plaintext, private_key))

#This will generate and return all required RSA information
def generate_rsa_info():
    #Generate RSA Key Pair
    rsa_keys = RSA.generate(2048)
    
    #Extract the public and private keys
    private_key = rsa_keys.export_key()
    public_key = rsa_keys.public_key().export_key()
    
    cipher = PKCS1_OAEP.new(rsa_keys)

    ret_tuple = (public_key, private_key, cipher)
    print(f"\n{ret_tuple[0]} \n\n {ret_tuple[1]}\n")
    return ret_tuple


#Get the digital signature of a message using server private key.
def get_message_signature(message, private_key):
    hash_obj = SHA256.new(message.encode())
    signer = pkcs1_15.new(RSA.import_key(private_key))
    signature = signer.sign(hash_obj)
    return signature


#Handles the RSA communication and returns the decrupted AES key
def rsa_exchange(client):
    rsa_info = generate_rsa_info()
    private_key = rsa_info[1]
    send_one_message(client, rsa_info[0])

    received_encrypted_key = recv_one_message(client)
    print(f"--Received encrypted AES key from client--\n{received_encrypted_key}")

    #Decrypt the AES key using our RSA private key
    decrypted_AES_key = rsa_info[2].decrypt(received_encrypted_key)
    return decrypted_AES_key, private_key
    

#Main execution starts here
def main():
    while True:
        #Server connection stuff
        print("Awaiting new Client")
        client, addr = socket.accept() 
        print("Client Connected")

        #The first thing that needs to be received from the client is the AES mode we will be using.
        client_AES_mode = recv_one_message(client)
        print(f"AES mode received: {client_AES_mode}")

        #Do RSA exchange and return AES key
        decrypted_AES_key, private_key = rsa_exchange(client)

        #Print the decrypted AES Key
        print(f"\n--Decrypted AES KEY--{decrypted_AES_key}\n")



        #Execute this IF block if the mode is ECB
        if client_AES_mode == b"ECB":
            #Create the AES object with the key
            cipher = AES.new(decrypted_AES_key, AES.MODE_ECB)
            communcation_loop(client, cipher, addr, private_key)

        #Execute this IF block if the mode is CCB
        elif client_AES_mode == b"CBC":
            #Receive the iv from the client.
            received_iv = recv_one_message(client)
            print(f"--Received iv from client--\n{received_iv}")

            #CBC mode is stateful meaning the same object cannot encrypt and decrypt.  This is why we need a decryption and encryption cipher object
            enc_cipher = AES.new(decrypted_AES_key, AES.MODE_CBC, received_iv)
            dec_cipher = AES.new(decrypted_AES_key, AES.MODE_CBC, received_iv)

            communcation_loop(client, enc_cipher, addr, private_key, dec_cipher)

        #Execute this IF block if the mode is OFB
        elif client_AES_mode == b"OFB":
            #Receive the iv from the client.
            received_iv = recv_one_message(client)
            print(f"--Received iv from client--\n{received_iv}")

            #OFB mode is stateful meaning the same object cannot encrypt and decrypt.  This is why we need a decryption and encryption cipher object
            enc_cipher = AES.new(decrypted_AES_key, AES.MODE_OFB, received_iv)
            dec_cipher = AES.new(decrypted_AES_key, AES.MODE_OFB, received_iv)

            communcation_loop(client, enc_cipher, addr, private_key, dec_cipher)

        
        else:
            print(f"Problem with reveived AES mode: {client_AES_mode}")


    

#Start execution
main()