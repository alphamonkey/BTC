import base58
import ecdsa
import hashlib
def privateKeytoWif(key_hex):
	return base58.b58encode_check(chr(0) + key_hex.decode('hex'))

def keyToAddr(s):
	return publicKeyToAddress(privateKeyToPublicKey(s))
def publicKeyToAddress(s):
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(s).digest())
	byteString = chr(0) + ripemd160.digest() 
	return base58.b58encode_check(byteString)
def privateKeyToPublicKey(s):
	sk = ecdsa.SigningKey.from_string(s, curve=ecdsa.SECP256k1)
	vk = sk.verifying_key
	return ('\04' + vk.to_string())
