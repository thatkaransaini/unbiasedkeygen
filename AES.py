import Crypto.Cipher.AES
import Crypto.Util.Counter

key = "0123456789ABCDEF" #
plaintext = "Attack at dawn"

ctr = Crypto.Util.Counter.new(128)
for x in range(0,100):
	cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CTR, counter=ctr)
	print cipher.encrypt(plaintext).encode('hex')