# Ho va ten: Tạ Đặng Vĩnh Phúc
# MSSV: B1709618
# STT: 50
import streamlit as st
import pandas as pd
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import DES

import math
import base64


#
# Class for sharing server session 
#

try:
    import streamlit.ReportThread as ReportThread
    from streamlit.server.Server import Server
except Exception:
    # Streamlit >= 0.65.0
    import streamlit.report_thread as ReportThread
    from streamlit.server.server import Server

class SessionState(object):
    def __init__(self, **kwargs):
        for key, val in kwargs.items():
            setattr(self, key, val)

def sess_get(**kwargs):
    '''Gets a SessionState object for the current session.
    Creates a new object if necessary'''
    # Hack to get the session object from Streamlit.
    ctx = ReportThread.get_report_ctx()

    this_session = None

    current_server = Server.get_current()
    if hasattr(current_server, '_session_infos'):
        # Streamlit < 0.56
        session_infos = Server.get_current()._session_infos.values()
    else:
        session_infos = Server.get_current()._session_info_by_id.values()

    for session_info in session_infos:
        s = session_info.session
        if (
            # Streamlit < 0.54.0
            (hasattr(s, '_main_dg') and s._main_dg == ctx.main_dg)
            or
            # Streamlit >= 0.54.0
            (not hasattr(s, '_main_dg') and s.enqueue == ctx.enqueue)
            or
            # Streamlit >= 0.65.2
            (not hasattr(s, '_main_dg') and s._uploaded_file_mgr == ctx.uploaded_file_mgr)
        ):
            this_session = s

    if this_session is None:
        raise RuntimeError(
            "Oh noes. Couldn't get your Streamlit Session object. "
            'Are you doing something fancy with threads?')
    if not hasattr(this_session, '_custom_session_state'):
        this_session._custom_session_state = SessionState(**kwargs)

    return this_session._custom_session_state


#
# RSA method
#

def generate_key():
    key = RSA.generate(1024)
    return key.publickey().exportKey('PEM'),  key.exportKey('PEM')

def encrypt_rsa(txt, pub):
    # print(txt, type(txt))
    txt = bytes(txt, encoding='utf8')
    pub = bytes(pub, encoding='utf8')
    pub = RSA.import_key(pub)
    cipher = PKCS1_v1_5.new(pub)
    # print(cipher)
    entxt = cipher.encrypt(txt)
    entxt = base64.b64encode(entxt)
    return str(entxt, encoding='utf8')

def decrypt_rsa(txt, priv):
    txt = base64.b64decode(txt)
    priv = RSA.import_key(priv)
    cipher = PKCS1_v1_5.new(priv)
    # dsize = SHA.digest_size
    sentinel = 123 # Random.new().read(15+dsize) 
    detxt = cipher.decrypt(txt, sentinel)
    return str(detxt, encoding='utf8')

def rsa():
    st.write("# RSA encrypt and decrypt")
    plainHolder = st.empty() 
    cipherHolder = st.empty() 
    pubKeyHolder = st.empty()
    privKeyHolder = st.empty()
    states = sess_get(rsa_plain='', rsa_cipher='', rsa_privKey='', rsa_pubKey='')
    btnGenerate = st.button('Generate key')
    btnEnc = st.button('Encrypt')
    btnDec = st.button('Decrypt')

    if btnGenerate:
        states.rsa_pubKey, states.rsa_privKey = generate_key()
        states.rsa_pubKey = str(states.rsa_pubKey, encoding='utf8')
        states.rsa_privKey = str(states.rsa_privKey, encoding='utf8')
    states.rsa_pubKey = pubKeyHolder.text_area('Public key', value=states.rsa_pubKey, key=None,)
    states.rsa_privKey = privKeyHolder.text_area('Private key', value=states.rsa_privKey, key=None,)

    if btnEnc:
        states.rsa_plain = plainHolder.text_area('Plain text', value=states.rsa_plain, key=None,)
        states.rsa_cipher = encrypt_rsa(states.rsa_plain, states.rsa_pubKey)
        states.rsa_cipher = cipherHolder.text_area('Cipher text', value=states.rsa_cipher, key=None,)
    
    if btnDec:
        states.rsa_cipher = cipherHolder.text_area('Cipher text', value=states.rsa_cipher, key=None, )
        states.rsa_plain = decrypt_rsa(states.rsa_cipher, states.rsa_privKey)
        plain = plainHolder.text_area('Plain text', value=states.rsa_plain, key=None, )
    
    if not (btnEnc or btnDec):
        states.rsa_plain = plainHolder.text_area('Plain text', value=states.rsa_plain, key=None,)
        states.rsa_cipher = cipherHolder.text_area('Cipher text', value=states.rsa_cipher, key=None,)

#
# DES method
#

def pad(s):
	return s + (8-len(s)%8) * chr(8-len(s)%8)
def unpad(s):
	return s[:-ord(s[len(s)-1:])]

def encrypt_des(txtToEnc, key):
	txt = pad(txtToEnc).encode("utf8")
	key = pad(key).encode("utf8")
	cipher = DES.new(key, DES.MODE_ECB)
	entxt = cipher.encrypt(txt)
	entxt = base64.b64encode(entxt)
	return str(entxt, encoding='utf8')

def decrypt_des(txt, key):
	key = pad(key).encode("utf8")
	txt = base64.b64decode(txt)
	cipher = DES.new(key, DES.MODE_ECB)
	detxt = unpad(cipher.decrypt(txt))
	return str(detxt, encoding='utf8')

def des():
    st.write("# DES encrypt and decrypt")
    plainHolder = st.empty() 
    cipherHolder = st.empty() 
    keyHolder = st.empty()
    states = sess_get(des_plain='', des_cipher='', des_key='') 
    # function button 
    btnEnc = st.button('Encrypt')
    btnDec = st.button('Decrypt')

    if btnEnc:
        states.des_cipher = encrypt_des(states.des_plain, states.des_key)
    if btnDec:
        states.des_plain = decrypt_des(states.des_cipher, states.des_key)
    states.des_plain = plainHolder.text_area('Plain text', value=states.des_plain, key=None,)
    states.des_cipher = cipherHolder.text_area('Cipher text', value=states.des_cipher, key=None,)
    states.des_key = keyHolder.text_area('Key', value=states.des_key, key=None,)


#
# AF encryption method
#
def xgcd(a, m):
	temp = m
	x0, x1, y0, y1 = 1, 0, 0, 1
	while m!=0:
		q, a, m = a // m, m, a % m
		x0, x1 = x1, x0 - q * x1
		y0, y1 = y1, y0 - q * y1
	if x0 < 0: 
		x0 = temp+x0
	return x0

def decrypt_af(txt, a, b, m):
	r = ''
	a1 = xgcd(a, m)
	for c in txt:
		e = (a1*(ord(c)-ord('A')-b)) % m
		r = r+chr(e+ord('A'))
	return r

def encrypt_af(txt, a, b, m):
	result = ''
	for c in txt:
		result += chr((a*(ord(c) - ord('A')) + b) % m + ord('a'))
	return result

def affine():
    st.write("# Affine encrypt and decrypt")
    plainHolder = st.empty() 
    cipherHolder = st.empty() 
    keyHolderA = st.empty()
    keyHolderB = st.empty()
    states = sess_get(af_plain='', af_cipher='', af_key_a='', af_key_b='')
    st.write('Affine modulo: 26')
    
    # function button 
    btnEnc = st.button('Encrypt')
    btnDec = st.button('Decrypt')
    
    if btnEnc:
        states.af_cipher = encrypt_af(states.af_plain, int(states.af_key_a), int(states.af_key_b), 26)
    if btnDec:
        states.af_plain = decrypt_af(states.af_cipher, int(states.af_key_a), int(states.af_key_b), 26)

    states.af_plain = plainHolder.text_area('Plain text', value=states.af_plain, key=None,)
    states.af_cipher = cipherHolder.text_area('Cipher text', value=states.af_cipher, key=None,)
    states.af_key_a = keyHolderA.text_input('A', value=states.af_key_a, key=None,)
    states.af_key_b = keyHolderB.text_input('B', value=states.af_key_b, key=None,)

def main():
    algos = ['DES', 'RSA', 'Affine']
    chosenAlgo = st.radio('Choose Encryption type', algos)

    # save all session variables
    sess_get(
        rsa_plain='', rsa_cipher='', rsa_privKey='', rsa_pubKey='', 
        des_plain='', des_cipher='', des_key='',
        af_plain='', af_cipher='', af_key_a='5', af_key_b='7'
    )

    if chosenAlgo == 'DES':
        des()
    elif chosenAlgo == 'RSA': 
        rsa()
    elif chosenAlgo == 'Affine':
        affine()
    else: 
        st.write("Unsuported algo")

main()