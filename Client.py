import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import sys
import time
from HelperMethods import *
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

"""
Names: Hunter Campbell, Carlos Nieves
Description: Client Server program for secret communication.  Makes use of RSA public keys to share an AES private key for communication
"""

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


#This handles the communicaton loops for CBC, ECB and OFB
#Since ECB is not stateful while CBC and OFB are stateful, this function can take an optional paramater for the stateful ciphers
#The optional paramater is for a secondary decryption cipher object to go along with the main cipher object.
def communication_loop(server, cipher, public_key, *optional_decryption_cipher):

    #Check if the optional decryption cipher is empty or not
    #By default python handles optional paramaters as Tuples, which is why I am measuring the len of the paramater and why accessing the parameter requires an index IE optional_param[0]
    if len(optional_decryption_cipher) <= 0:
        #This block is executed for ECB since it isnt stateful (the optional decryption cipher tuple will be empty)
        while True:
            user_message_plaintext = input("\nPlease enter a message to be encrypted and sent to the server: ")
            encrypt_and_send(user_message_plaintext.encode(), server, cipher)

            #Following code block receives the message + signature.  Then checks if the signature is valid (go to the check_signature function for more information)
            received_cipher_text = recv_one_message(server)
            received_sig = recv_one_message(server)
            received_plain_text = decrypt_and_display(received_cipher_text, cipher)
            print(f"\nDigital signature: {received_sig}")
            check_signature(received_plain_text, received_sig, public_key)
            if(received_plain_text == "bye!"):
                encrypt_and_send("bye!".encode(), server, cipher)
                #Give the server 1 second to receive the response from the client
                time.sleep(1)
                break
    else:
        #This block is executed for CBC and OFB since it is stateful (the optional decryption cipher tuple isnt empty)
        while True:
            user_message_plaintext = input("\nPlease enter a message to be encrypted and sent to the server: ")
            encrypt_and_send(user_message_plaintext.encode(), server, cipher)

            #Following code block receives the message + signature.  Then checks if the signature is valid (go to the check_signature function for more information)
            received_cipher_text = recv_one_message(server)
            received_sig = recv_one_message(server)
            received_plain_text = decrypt_and_display(received_cipher_text, cipher, optional_decryption_cipher[0])
            print(f"\nDigital signature: {received_sig}")
            check_signature(received_plain_text, received_sig, public_key)
            if(received_plain_text == "bye!"):
                encrypt_and_send("bye!".encode(), server, cipher)
                #Give the server 1 second to receive the response from the client and properly shutdown
                time.sleep(1)
                break


#Encrypt a message with a given RSA public key
def encrypt_message_with_rsa_pubkey(message, public_key):
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    enc_message = cipher.encrypt(message)
    return enc_message


#Sends AES key to server using RSA key as encryption method
def rsa_exchange(AES_key, server):
    #Receive the RSA public key from the server
    rsa_pub_key = recv_one_message(server)
    print(f"--Public key received from server--\n{rsa_pub_key}")
    #Encrypt AES key with received RSA key
    encrypted_AES_key = encrypt_message_with_rsa_pubkey(AES_key, rsa_pub_key)
    print(f"\n--Encrypted AES key with RSA public key--\n{encrypted_AES_key}")
    #Send encrypted AES key to the server
    send_one_message(server, encrypted_AES_key)
    return rsa_pub_key


#Check if a signature matches a message received
def check_signature(plaintext_message, signature, public_key):
    #Hash the received plaintext and then compare that to the received signature (which is also a hash) that has been decrypted using the RSA public key
    hash_obj = SHA256.new(plaintext_message.encode())
    verifier = pkcs1_15.new(RSA.import_key(public_key))
    try:
        verifier.verify(hash_obj, signature)
        print("\nSignature is valid.")
    except (ValueError, TypeError):
        print("\nSignature is invalid.")


#Execution starts here
def main():
    #Socket setup and connection stuff
    server = socket.socket()             
    port = 52222      
    server.connect(('127.0.0.1', port))  

    #The first thing that needs to be sent to the server is the AES mode we will be using. 
    send_one_message(server, args[2])

    #Generate an AES key with the given bit length converted to byte length
    AES_key = get_random_bytes(int(int(args[1]) / 8))
    print(f"\n--The generated AES key--\n{AES_key}\n")

    #Sends AES key to server, also get public key
    public_key = rsa_exchange(AES_key, server)
    

    #Execute this IF block if EBC is selected as the mode
    if args[2] == "ECB":
        #Create the AES object with the key
        cipher = AES.new(AES_key, AES.MODE_ECB)
        communication_loop(server, cipher, public_key)
        
    #Execute this IF block if CBC is selected as the mode
    elif args[2] == "CBC":
        #Create and send the IV to the server.  IV is 16 bytes same as a block
        iv = get_random_bytes(16)
        print(f"\n--The generated iv is--\n{iv}")
        send_one_message(server, iv)

        #CBC mode is stateful meaning the same object cannot encrypt and decrypt.  This is why we need a decryption and encryption cipher object
        enc_cipher = AES.new(AES_key, AES.MODE_CBC, iv)
        dec_cipher = AES.new(AES_key, AES.MODE_CBC, iv)
        communication_loop(server, enc_cipher, public_key, dec_cipher)

    #Execute this IF block if OFB is selected as the mode
    elif args[2] == "OFB":
        #Create and send the IV to the server.  IV is 16 bytes same as a block
        iv = get_random_bytes(16)
        print(f"\nThe generated iv is {iv}\n")
        send_one_message(server, iv)

        #OFB mode is stateful meaning the same object cannot encrypt and decrypt.  This is why we need a decryption and encryption cipher object
        enc_cipher = AES.new(AES_key, AES.MODE_OFB, iv)
        dec_cipher = AES.new(AES_key, AES.MODE_OFB, iv)

        communication_loop(server, enc_cipher, public_key, dec_cipher)
main()
print("\nClient shut down")