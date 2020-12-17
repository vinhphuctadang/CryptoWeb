# Ho va ten: Tạ Đặng Vĩnh Phúc
# MSSV: B1709618
# STT: 50
import streamlit as st
import pandas as pd
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import MD5, SHA1, SHA256, SHA512
from Crypto.Cipher import PKCS1_v1_5
import base64
import os 

#
# CORE API
#
def getHash(s, hashAlgo):
    '''Returns the hash value with desired algos'''
    hashAlgo = hashAlgo.lower()
    content = bytes(s, encoding='utf8')
    if hashAlgo == 'md5':
        result = MD5.new(content)
    elif hashAlgo == 'sha1':
        result = SHA1.new(content)
    elif hashAlgo == 'sha256':
        result = SHA256.new(content)
    elif hashAlgo == 'sha512':
        result = SHA512.new(content)
    else:
        raise ValueError("Unsupported hash algo: %s" % hashAlgo)
    hsh = result.hexdigest().upper()
    return hsh

def main():
    st.write(
        '''
        # Application using hash algos: Login form
        '''
    )
    name = st.text_input('Input name', value='', key=None, type='default')
    password = st.text_input('Input password', value='', key=None, type='password')
    
    if os.path.isfile('./csdl.csv'):
        db = pd.read_csv('./csdl.csv')
    else:
        db = pd.DataFrame({
            'username': [],
            'password': []
        })
    
    btnLogin = st.button('Login')
    if btnLogin and name and password:
        # check name existence first
        if len(db[(db['username'] == name) & (db['password'] == getHash(password, 'md5'))]):
            st.write("Account loggedin")
        else:
            st.write("Invalid username or password")
    
main()