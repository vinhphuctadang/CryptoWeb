import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

plaintext = b'{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; patigon, elsa'
key = get_random_bytes(32)
cipher = ChaCha20.new(key=key)
ciphertext = cipher.encrypt(plaintext)
nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ciphertext).decode('utf-8')
result = json.dumps({'nonce': nonce, 'ciphertext': ct}) 
print("Encrypted result:", result)

# decryption by chunk by chunk
json_input = result
b64 = json.loads(json_input)
nonce = b64decode(b64['nonce'])
ciphertext = b64decode(b64['ciphertext'])
cipher = ChaCha20.new(key=key, nonce=nonce)

plaintext = cipher.decrypt(ciphertext[:64])
print("The message was", plaintext) 

plaintext = cipher.decrypt(ciphertext[64:])
print("The message was", plaintext) 