'''
Họ và tên: Tạ Đặng Vĩnh Phúc
MSSV: B1709618
STT: 50
'''

# import libs
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5
import base64

# in practice/product, we should not use import *
from tkinter import *
from tkinter import filedialog

# assign global values representing controls
pri_key, pub_key, plaintxt, ciphertxt, encryptedtxt, decryptedtxt = None, None, None, None, None, None

def save_file(content, _mode, _title, _filetypes, _defaultextension):
    f = filedialog.asksaveasfile(mode=_mode, initialdir="./", title=_title, filetypes=_filetypes, defaultextension=_defaultextension)
    if f is None: 
        print('No file chosen, skip saving')
        return 
    f.write(content)
    f.close()

def generate_key():
    key = RSA.generate(1024)
    # pri = save_file(key.exportKey('PEM'),
    #     'wb',
    #     'Lưu khóa cá nhân',
    #     (("All files", "*.*"), ("PEM files", "*.pem")),
    #     ".pem")
    # pub = save_file(
    #     key.publickey().exportKey('PEM'),
    #     'wb',
    #     'Lưu khóa công khai',
    #     (("All files", "*.*"),("PEM files", "*.pem")),
    #     ".pem"
    # )
    pri_key.delete(1.0, 'end')
    pri_key.insert(1.0, key.exportKey('PEM'))
    pub_key.delete(1.0, 'end')
    pub_key.insert(1.0, key.publickey().exportKey('PEM'))

def encrypt_rsa():
    txt = plaintxt.get(1.0, 'end').encode()
    pub = RSA.import_key(pub_key.get(1.0, 'end').encode())
    
    cipher = PKCS1_v1_5.new(pub)
    # print(cipher)
    entxt = cipher.encrypt(txt)
    entxt = base64.b64encode(entxt)
    ciphertxt.delete(1.0, 'end')
    ciphertxt.insert(1.0, entxt)

def decrypt_rsa():
    
    # print()
    txt = ciphertxt.get(1.0, 'end').encode()
    txt = base64.b64decode(txt)
    priv = RSA.import_key(pri_key.get(1.0, 'end').encode())
    cipher = PKCS1_v1_5.new(priv)

    # dsize = SHA.digest_size
    sentinel = 123 # Random.new().read(15+dsize) 
    detxt = cipher.decrypt(txt, sentinel)
    # entxt = base64.b64encode(entxt)
    decryptedtxt.delete(1.0, 'end')
    decryptedtxt.insert(1.0, detxt)

def main():
    global pri_key, pub_key, plaintxt, encryptedtxt, decryptedtxt, ciphertxt
    # Init screen
    window = Tk()
    window.title("CHƯƠNG TRÌNH DEMO RSA")

    # Add title and controls
    lb0 = Label(window, text=" ",font=("Arial Bold", 10))
    lb0.grid(column=0, row=0)
    lbl = Label(window, text="CHƯƠNG TRÌNH DEMO MẬT MÃ BẤT ĐỐI XỨNG RSA",font=("Arial Bold", 20))
    lbl.grid(column=1, row=1)
    plainlb3 = Label(window, text="Văn bản gốc",font=("Arial", 14))
    plainlb3.grid(column=0, row=3)

    plaintxt = Text(window, height=5, borderwidth=2, relief="groove")
    plaintxt.grid(column=1, row=3)

    plainlb3 = Label(window, text="Văn bản đã được mã hoá",font=("Arial", 14))
    plainlb3.grid(column=0, row=4)
    ciphertxt = Text(window, height=5, borderwidth=2, relief="groove")
    ciphertxt.grid(column=1, row=4)

    plainlb3 = Label(window, text="Văn bản đã được giải mã",font=("Arial", 14))
    plainlb3.grid(column=0, row=5)
    decryptedtxt = Text(window, height=5, borderwidth=2, relief="groove")
    decryptedtxt.grid(column=1, row=5)
    
    plainlb3 = Label(window, text="Khoá cá nhân",font=("Arial", 14))
    plainlb3.grid(column=0, row=6)
    pri_key = Text(window, height=5, borderwidth=2, relief="groove")
    pri_key.grid(column=1, row=6)

    plainlb3 = Label(window, text="Khoá công khai",font=("Arial", 14))
    plainlb3.grid(column=0, row=7)
    pub_key = Text(window, height=5, borderwidth=2, relief="groove")
    pub_key.grid(column=1, row=7)

    # Create buttons and config event handlers
    createKeyBtn = Button(window, text="Tạo khoá", width=50, height=2, command=generate_key)
    createKeyBtn.grid(column=1, row=9)

    encBtn = Button(window, text="Mã hoá", width=50, height=2, command=encrypt_rsa)
    encBtn.grid(column=1, row=10)

    decBtn = Button(window, text="Giải mã", width=50, height=2, command=decrypt_rsa)
    decBtn.grid(column=1, row=11)

    window.geometry('800x600')
    window.mainloop()
main()