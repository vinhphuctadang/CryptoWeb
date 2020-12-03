import streamlit as st
import pandas as pd
from Crypto.Cipher import DES
import base64

def pad(s):
	return s + (8-len(s)%8) * chr(8-len(s)%8)
def unpad(s):
	return s[:-ord(s[len(s)-1:])]

def encrypt(txtToEnc, key):
	txt = pad(txtToEnc).encode("utf8")
	key = pad(key).encode("utf8")
	cipher = DES.new(key, DES.MODE_ECB)
	entxt = cipher.encrypt(txt)
	entxt = base64.b64encode(entxt)
	return entxt
# 
# Main web page
#
#
def main():
    st.write(
        '''
        # My first app for cryptography

        ## DES encryption
        '''
    )

    key = st.text_input('Input key', value='', max_chars=8, key=None, type='default')
    if not key:
        st.write('Please input key of 8 bytes, our server wont save the key')

    file_bytes = st.file_uploader("Upload a file")
    if file_bytes:
        st.write(
            '''# File content overview:
            '''
        )
        # TODO: Use stat instead
        data = str(file_bytes.read(), encoding='utf8')
        st.write('File size:', len(data))

        encrypted = encrypt(data, key)
        st.write(data[:min(1000, len(data))])

        st.write('# Encrypted file:')
        st.write(encrypted)

        # import time, json
        # from random import randint
        # fileName = '%d%d.enc' % (int(time.time()), randint(0, 10000))
        # with open(fileName, 'wb') as f:
        #     f.write(encrypted)

        # link = '# [Link](/%s)' % fileName
        # st.markdown(link, unsafe_allow_html=True)

main()