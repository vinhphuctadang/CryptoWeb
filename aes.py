from Crypto.Cipher import AES

partA = b'Hello world is e'
partB = b'ncrypted hello P' 
data = partA + partB
key = b'Sixteen byte key'

# nonce = b'0'
cipher = AES.new(key, AES.MODE_GCM, nonce=b'0')
ciphertext = cipher.encrypt(data)
print("Plain text:", data, len(data)) # , nonce)
print("Cipher text:", ciphertext.hex(), len(ciphertext))

# partial decryption, using the same key object
nonce = b'0'
cipher = AES.new(key, AES.MODE_GCM, nonce=b'0') # , nonce=nonce)
tmp_ciphertext = ciphertext[:16]
decrypted_text = cipher.decrypt(tmp_ciphertext)
print("Decrypted text:", decrypted_text)

tmp_ciphertext = ciphertext[16:]
decrypted_text = cipher.decrypt(tmp_ciphertext)
print("Decrypted text:", decrypted_text)

