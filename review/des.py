# from Crypto.Cipher import DES
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
def decrypt(txt, key):
	key = pad(key).encode("utf8")
	txt = base64.b64decode(txt)
	cipher = DES.new(key, DES.MODE_ECB)
	detxt = unpad(cipher.decrypt(txt))
	return detxt
