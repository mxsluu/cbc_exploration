from modes import *
from Crypto.Cipher import AES

def submit(user_input, cipher, iv):
    start = "userid=456;userdata="
    end = ";session-id=31337"
    modified_user_input = ''
    for char in user_input:
        if char == ';':
            modified_user_input = modified_user_input + '%3B'
        elif char == '=':
            modified_user_input = modified_user_input + '%3D'
        else:
            modified_user_input = modified_user_input + char
    modified_user_input = start + modified_user_input + end
    modified_user_input = pad(modified_user_input.encode('utf-8'))
    return cbc_encrypt(modified_user_input, cipher, iv)

def verify(encrypted_input, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    d = cipher.decrypt(encrypted_input)
    if b";admin=true;" in d:
        return True
    return False


def weaponize(encrypted):
    semicolon1 = encrypted[4] ^ ord(';') ^ ord('1') # Weaponizes the string 1admin2true1
    semicolon2 = encrypted[15] ^ ord(';') ^ ord('1') # 1 are semicolons and 2 is a equal sign
    equal_sign = encrypted[10] ^ ord('=') ^ ord('2')
    payload = bytearray(encrypted)
    payload[4] = semicolon1
    payload[10] = equal_sign
    payload[15] = semicolon2
    return bytes(payload)



