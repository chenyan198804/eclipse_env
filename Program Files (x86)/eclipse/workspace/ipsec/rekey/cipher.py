from Crypto.Cipher import DES3
import binascii
import string
from Crypto.Hash import HMAC
from Crypto.Hash import SHA

def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    
    return reduce(lambda x,y:x+y, lst)
#convert hex repr to string
def toStr(s):
    return s and chr(string.atoi(s[:2], base=16)) + toStr(s[2:]) or ''

ENCRYPTION_ALGOS = {'AES-CBC' :      ['AES',     'CBC', 16,   [16,24,32]],
                   'AES-CTR' :      ['AES',     'CTR',  8,    [20,28,36]],
                   'DES-CBC' :      ['DES',     'CBC',  8,    [8]],
                   'BLOWFISH-CBC' : ['Blowfish','CBC',  8,    [-1]],
                   '3DES-CBC' :     ['DES3',    'CBC',  8,    [24]],
                   'CAST5-CBC' :    ['CAST',    'CBC',  8,    [5,6,7,8,9,10,11,12,13,14,15,16]],
                   'NULL' :         [None,      None,   0,    [-1]]}
                   
ESP_algos_auth = {'HMAC-SHA1-96'        : ['HMAC',      'SHA',      12,[-1]],
                  'HMAC-SHA256-96'      : ['HMAC',      'SHA256',   12,[-1]],
                  'HMAC-MD5-96'         : ['HMAC',      'MD5',      12,[-1]],
                  'AES-XCBC-MAC-96'     : ['XCBCMAC',   'AES',      12,[16]],
                  'HMAC-RIPEMD160-96'   : ['HMAC',      'RIPEMD',   12,[-1]],
                  'NULL'                : [None,        None,       0,[-1]]}
                  
iv = binascii.a2b_hex('839656118f5d134e')
key = binascii.a2b_hex('6000F1D950B4690847185CAC483E71D3B58AD9F433E21A75')
des3 = DES3.new(key, DES3.MODE_CBC, iv)
des3_1 = DES3.new(key, DES3.MODE_CBC, iv)
text = 'abcdefgh'
cipher_text = des3.encrypt(text)
print "type(cipher_text) is " + str(type(cipher_text))
print toHex(cipher_text)            #e2891c4c

esp_algo_crypt = "3DES-CBC"
cipher = ENCRYPTION_ALGOS[esp_algo_crypt][0]            
try:
    esp_ciph = eval(cipher)
except NameError:
    raise Exception('module <' + cipher + '> not available')
esp_ciph_block_size = esp_ciph.block_size                
esp_iv_len = ENCRYPTION_ALGOS[esp_algo_crypt][2]
# esp_key_crypt = IPSEC_SAD().check_key(esp_key_crypt,esp_algo_crypt)
esp_key_crypt = key
esp_key_len_crypt = len(esp_key_crypt)
esp_iv = iv
enc=esp_ciph.new(esp_key_crypt, esp_ciph.MODE_CBC, IV=esp_iv)
esp_ciph.key_size = esp_key_len_crypt
encrypt_data = enc.encrypt(text)
print "type(cipher_text) is " + str(type(cipher_text))
print toHex(cipher_text)            #e2891c4c

                
# cipher_text = binascii.a2b_hex(a)
# print a
# print cipher_text
# print des3_1.decrypt(cipher_text)

'''
hex_text = "b06ef701233c46e909747fbb23e678cb437dca291b2b59115d311cf552bb5a261aeed857b92cb447d5442b332d3987d8d3861b76dcf8276c6977caf7f8866d6277d3d32d56abdb2575dd43a519038a94fcc27ff613b1f7e667f5cb7dbbdfc2d396ecc281e81b780f1b4c45aa625d95318ef962a7c0e26308295ed934b6740b2d3e2b0f125158de3355c009ba14093dddeacac875e5b69bdd"
cipher_text = binascii.a2b_hex(hex_text)
# print "cipher_text is " + toHex(cipher_text)
print "plaintext is" + toHex(des3.decrypt(cipher_text))

# cipher_text = "2700000c010000000a45c4f92100001c02000000478921a8dc3732f15007b3b5c1d686d1e3112dd92c0000280000002401030403c64071ec0300000801000003030000080300000200000008050000002d00001801000000070000100000ffffac100001ac1000012900001801000000070000100000ffff0a45c42f0a45c42f29000008000040140000000800004021df9c60e9179cab07"
hmac_key = binascii.a2b_hex('E5D51B8171AD4E448B390F4868A0EE98EBD9546B')
# print "hmac_key is " + toHex(hmac_key)
# hmac_key = binascii.a2b_hex('A52B648113E309899CC6993CAD58190D0379B1CE')
# SHA.digest_size = 8
hmac = HMAC.new(hmac_key, msg = cipher_text, digestmod = SHA)
# hmac.update(cipher_text)
print "hex digest is " + hmac.hexdigest()
# print (hmac.new(hmac_key, cipher_text, hashlib.sha1, digest_size=8).hexdigest())
'''

iv = binascii.a2b_hex('af3cd1900ee0d879')
key = binascii.a2b_hex('444e62a164b8d8daab7c4daaca6d379c491841a2fc7b9292')
des3 = DES3.new(key, DES3.MODE_CBC, iv)
hex_text = "00000008010000003c8751efd19bb607"
cipher_text = binascii.a2b_hex(hex_text)
print toHex(des3.decrypt(cipher_text))