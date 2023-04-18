import struct
from Crypto.Util.Padding import pad, unpad

"""
Names: Hunter Campbell, Carlos Nieves
Description: Client Server program for secret communication.  Makes use of RSA public keys to share an AES private key for communication

"""

AES_BLOCK_SIZE_BYTES = 16

#Receive a single message from a remote host (not really remote in this program but name felt appropriate)
def recv_one_message(remote_host):
    lengthbuf = recvall(remote_host, 4)
    length, = struct.unpack('!I', lengthbuf)
    return recvall(remote_host, length)

#Use a loop to receive the entirety of a message (useful for very large input)
def recvall(remote_host, count):
    buf = b''
    while count:
        newbuf = remote_host.recv(count)
        if not newbuf: return None
        buf += newbuf
        count -= len(newbuf)
    return buf

#Send a single message to a host.  Able to identify if the type is already in byte format or in string format and execute accordingly
def send_one_message(remote_host, message):
    if(isinstance(message, str)):
        length = len(message)
        remote_host.sendall(struct.pack('!I', length))
        remote_host.sendall(message.encode())
    else:
        length = len(message)
        remote_host.sendall(struct.pack('!I', length))
        remote_host.sendall(message)

#Encrypt and send a message to a host.  Takes in the cipher of choice, then encrypts and pads the message.  Passes this to the send_one_message function
def encrypt_and_send(message, remote_host, cipher):
    cipher_text = cipher.encrypt(pad(message, AES_BLOCK_SIZE_BYTES))
    if message != "bye!".encode():
        print(f"The cipher text for your message is: {cipher_text}")
    send_one_message(remote_host, cipher_text)

#Takes in a cipher and cipher text, then decrypts and displays the message.
def decrypt_and_display(cipher_text, cipher, *optional_decryption_cipher):
    print(f"\nThe cipher text received is {cipher_text}")
    if len(optional_decryption_cipher) <= 0:
        plaintext = cipher.decrypt(cipher_text)
    else:
        plaintext = optional_decryption_cipher[0].decrypt(cipher_text)
    unpadded_plaintext = unpad(plaintext, AES_BLOCK_SIZE_BYTES)
    print(f"Decrypted plaintext: {unpadded_plaintext.decode()}")
    return unpadded_plaintext.decode()
