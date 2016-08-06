##Main application
import random #For generating private key
import keyUtils
import utils
import ecdsa #for turning private key to public key
import hashlib #For hash256 and hash160

##Generating keys and addresses

#Random 256 bit prtivate key
private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
print("Private_key is " + str(len(private_key)) + " long " + str(type(private_key)) + " contence: " + str(private_key))


# Input is hex string, output is hex string, len(output) = 130
def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')

public_key = privateKeyToPublicKey(private_key)
print("Public_key is " + str(len(public_key)) + " long " + str(type(public_key)) + " contence: " + str(public_key))

def hash256(hbytes): #Returns 256 bit (32 bytes) raw hex  
	y = hashlib.sha256(hbytes).digest()
	y1 = hashlib.sha256(y).digest()
	return y1
#Hash160 is used for adresses
def hash160(hbytes): #Retuns 160 bit (20 bytes) raw hex 
	s = hashlib.new('sha256',hbytes).digest()
	r = hashlib.new('ripemd160', s).digest()
	return r

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n /= 58
    return result

def rawHexToDecimal(s): #Turns rawhex to decimal
	result = 0
	for c in s:
		#ord('\x0F') returns 15
		#We take 1 byte, 2 hex characters at a time. By multiplying by 256 we change the place value for the next byte
		result = result * 256 + ord(c)
	return result


#https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version,hbytes):
	print("\n Version = " + str(version))
	print("\n Hex Bytes = " + str(hbytes.encode('hex') + "\n"))
	s = chr(version) + hbytes #Char: Turns the version inputted as hex to raw hex
	print("Appended data  = " + str(s.encode('hex')))
	checksum = hash256(s)[0:4] #Takes the first 4 bytes of the hash256 returned bytes
	s = s + checksum #Append to the end
	base58 = base58encode(rawHexToDecimal(s)) #Convert to base58
	#Count the zeros
	numOfZeros = 0
	for c in s:
		if (c == "0"):
			numOfZeros+=1
	return ("1" * numOfZeros) + base58 #Adds the base58 ones to pad it out



# https://en.bitcoin.it/wiki/Wallet_import_format
def privateKeyToWif(key_hex):
	result = base58CheckEncode(0x80, key_hex.decode('hex'))
	print("Base58check received raw hex for both parameters and returned " + str(len(result)) + " long, were the type was " +str(type(result)))
	return result

wif =  privateKeyToWif(private_key)
print("WIF key is " + str(len(wif)) + " long " + str(type(wif)) + " content: " + str(wif))


#Getting out address from our public key

def pubKeyToAddr(s):
    return base58CheckEncode(0, hash160(s))

Address = keyUtils.pubKeyToAddr(public_key)
print("Address is " + str(len(Address)) + " long " + str(type(Address)) + " content: " + str(Address))


##
