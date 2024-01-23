import sys
from Crypto.Cipher import AES
from sys import byteorder


def exclusive_or(plaintext, previous_ct):
    plaintext_as_int = int.from_bytes(plaintext, sys.byteorder)
    prev_ct_as_int = int.from_bytes(previous_ct, sys.byteorder)
    return (plaintext_as_int ^ prev_ct_as_int).to_bytes(16, sys.byteorder)


def pad(plaintext):
    if 0 < len(plaintext) % 16 <= 15:  # Calculate if padding is needed
        next_multiple = (len(plaintext) // 16) + 1
        pad_amount = (next_multiple * 16) - len(plaintext)
        bytes_to_pad = pad_amount
        padding_bytes = bytearray()
        while bytes_to_pad != 0:  # pad until divisible by 16 bytes (128 bits)
            padding_bytes.append(pad_amount)
            bytes_to_pad -= 1
        return plaintext + padding_bytes
    return plaintext  # if padding is not needed just return the plaintext


def ecb_encrypt(plaintext, cipher):
    encrypted = []
    text = pad(plaintext)  # check for padding
    for i in range(0, len(text), 16):  # Loop through chunks of 128 bits (16 bytes) in text
        block = text[i:i + 16]  # get 16 bytes (128 bits) at a time form text
        encrypted.append(cipher.encrypt(block))  # Encrypt block and add to list of cipher blocks

    encrypted = b''.join(encrypted)  # Join all encrypted blocks into one
    return encrypted


def cbc_encrypt(plaintext, cipher, iv):
    encrypted = []
    prev_block = 0  # record previous cipher text block for next block
    text = pad(plaintext)  # check for padding
    for i in range(0, len(text), 16):  # Loop through chunks of 128 bits (16 bytes) in text
        p = text[i:i + 16]  # get 16 bytes (128 bits) at a time form text
        if i == 0:
            block = exclusive_or(p, iv)  # if first block, exclusive or plaintext and iv
        else:
            block = exclusive_or(p, prev_block)  # Else, use previous completed cipher block in next block
        prev_block = cipher.encrypt(block)  # Encrypt block and set new previous block
        encrypted.append(prev_block)  # add to list of current cipher blocks

    encrypted = b''.join(encrypted)  # Join all encrypted blocks into one
    return encrypted
