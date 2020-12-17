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

    algos = ['md5', 'sha1', 'sha256', 'sha512']
    # for algo in ['md5', 'sha1', 'sha256', 'sha512']:
    #    print(getHash('phuc', algo))
    st.write(
        '''
        # Application using hash algos
        '''
    )
    key = st.text_input('Input text', value='', key=None, type='default')
    if not key:
        st.write('Please input text to hashs')
    
    chosenAlgo = st.radio('Choose hash types', algos)
    if key:
        st.write('Hash output using %s:' % chosenAlgo)
        st.write(bytes(getHash(key, chosenAlgo), encoding='utf8'))
main()