import struct
from Crypto.Util.Padding import pad, unpad
AES_BLOCK_SIZE_BYTES = 16

def recv_one_message(remote_host):
    lengthbuf = recvall(remote_host, 4)
    length, = struct.unpack('!I', lengthbuf)
    return recvall(remote_host, length)


def recvall(remote_host, count):
    buf = b''
    while count:
        newbuf = remote_host.recv(count)
        if not newbuf: return None
        buf += newbuf
        count -= len(newbuf)
    return buf


def send_one_message(remote_host, message):
    if(isinstance(message, str)):
        length = len(message)
        remote_host.sendall(struct.pack('!I', length))
        remote_host.sendall(message.encode())
    else:
        length = len(message)
        remote_host.sendall(struct.pack('!I', length))
        remote_host.sendall(message)


def encrypt_and_send(message, server, cipher):
   
    cipher_text = cipher.encrypt(pad(message, AES_BLOCK_SIZE_BYTES))

    if message != "bye!".encode():
        print(f"The cipher text for your message is: {cipher_text}")

    send_one_message(server, cipher_text)


def decrypt_and_display(cipher_text, cipher, *optional_decryption_cipher):
    print(f"\nThe cipher text received is {cipher_text}")

    if len(optional_decryption_cipher) <= 0:
        plaintext = cipher.decrypt(cipher_text)
    else:
        plaintext = optional_decryption_cipher[0].decrypt(cipher_text)

    unpadded_plaintext = unpad(plaintext, AES_BLOCK_SIZE_BYTES)
    print(f"Decrypted plaintext: {unpadded_plaintext.decode()}")
    return unpadded_plaintext.decode()


