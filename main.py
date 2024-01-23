from modes import *
from server_simulator_funcs import *
from Crypto.Cipher import AES
from secrets import token_bytes

def main():

    key = token_bytes(16)
    iv = token_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    type_of_input = input("Please select which task (1 or 2): ")
    if type_of_input == "1":
        file_name = input("Please input the name of the file you wish to encrypt: ")
        mode = input("Please enter your preferred mode of operation (ECB or CBC): ")
        with open(file_name, "rb") as pt:
            data = pt.read()
        pt.close()
        header = data[0:54]
        plaintext = data[54:]
        if mode == "ECB":
            encrypted = ecb_encrypt(plaintext, cipher)
            end = "_ECB_encrypted.bmp"
        else:
            encrypted = cbc_encrypt(plaintext, cipher, iv)
            end = "_CBC_encrypted.bmp"

        encrypted = header + encrypted
        with open(file_name[:len(file_name) - 4] + end, "wb") as nf:
            nf.write(encrypted)
        nf.close()
        print("Done!")
    else:
        user_input = input("Please enter a string: ")
        encrypted = submit(user_input, cipher, iv)
        print("Checking string.....")
        encrypted = weaponize(encrypted)
        if not verify(encrypted, key, iv):
            print("Valid!")
        else:
            print("Invalid!")

if __name__ == "__main__":
    main()
