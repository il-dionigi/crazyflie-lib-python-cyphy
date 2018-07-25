import os

#Cryptography includes
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
import cryptography.hazmat.backends as backends
import cryptography.exceptions as CrypExc



key = bytes([0x57, 0x01, 0x2A, 0x12, 0xA7, 0x7A, 0x12, 0xBA, 0x57, 0x01, 0x2A, 0x12, 0xA7, 0x7A, 0x12, 0xBA])
#this should be a class
def encrypt(associated_data, plaintext):
    # Generate a random 96-bit IV.
    iv = os.urandom(4)
    

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=backends.default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (iv, encryptor.tag, ciphertext)

def decrypt(associated_data, iv, tag, ciphertext):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag, 4),
        backend=backends.default_backend()
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    
    decryptor.authenticate_additional_data(associated_data)


    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.

    return decryptor.update(ciphertext) + decryptor.finalize()

    
def setKey(newKey):
    try:
        key = newKey
    except TypeError:
        return "Wrong type, should be a bytes object"
        
    return None
    
    
    
    
    
    
    
    
    
