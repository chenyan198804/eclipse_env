from scapy.all import *
from Crypto.Cipher import DES3
from Crypto.Hash import HMAC
from Crypto.Hash import SHA

import inspect
import binascii
import string
import gmpy2
import os
import datetime
import struct


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

'''
class IKEv2_payload_Encrypted(IKEv2_class):
    name = "IKEv2 Encrypted and Authenticated"
    encrypt_mode = "3DES"
    overload_fields = { IKEv2: { "next_payload":46 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+12),
        #'Q' represents 8Bytes
        StrFixedLenField('iv', None, 8),
        StrLenField("load","",length_from=lambda x:x.length-12),
        ]
    
    def __init__(self, _pkt="", post_transform=None, _internal=0, _underlayer=None, **fields):
        self.time  = time.time()
        self.sent_time = 0
        if self.name is None:
            self.name = self.__class__.__name__
        self.aliastypes = [ self.__class__ ] + self.aliastypes
        self.default_fields = {}
        self.overloaded_fields = {}
        self.fields={}
        self.fieldtype={}
        self.packetfields=[]
        self.__dict__["payload"] = NoPayload()
#        if self.encrypt_mode == "3DES":
#            fields_desc = [
#                ByteEnumField("next_payload",None,IKEv2_payload_type),
#                ByteField("res",0),
#                FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+12),
#                #'Q' represents 8Bytes
#                StrLenField('iv', "", 8),
#                StrLenField("load","",length_from=lambda x:x.length-12),
#                ]
#        elif self.encrypt_mode == "AES_CBC":
#             fields_desc = [
#                ByteEnumField("next_payload",None,IKEv2_payload_type),
#                ByteField("res",0),
#                FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+20),
#                #'Q' represents 8Bytes
#                StrLenField('iv', "", 16),
#                StrLenField("load","",length_from=lambda x:x.length-20),
#                ]
        self.init_fields()
        self.underlayer = _underlayer
        self.initialized = 1
        if _pkt:
            self.dissect(_pkt)
            if not _internal:
                self.dissection_done(self)
        for f in fields.keys():
            self.fields[f] = self.get_field(f).any2i(self,fields[f])
        if type(post_transform) is list:
            self.post_transforms = post_transform
        elif post_transform is None:
            self.post_transforms = []
        else:
            self.post_transforms = [post_transform]
'''

#packets = rdpcap(r".\\ike_AES128.pcap")
#ikev2_payload_encrypted = packets[2]
#if ikev2_payload_encrypted.haslayer("IKEv2"):
#    init_vector_r   = ikev2_payload_encrypted[IKEv2_payload_Encrypted].iv + ikev2_payload_encrypted[IKEv2_payload_Encrypted].load[:4]
#    load = ikev2_payload_encrypted[IKEv2_payload_Encrypted].load[4:]
#    print toHex(init_vector_r)


'''
if ENCRYPTION_MODE == "3DES":
    des3_decrypt = DES3.new(SK_er, DES3.MODE_CBC, init_vector_r)
    decrypted_data = des3_decrypt.decrypt((ike_auth_r[IKEv2_payload_Encrypted].load)[:-12])
elif ENCRYPTION_MODE == "AES_CBC":
    aes_cbc_decrypt = AES.new(SK_er, AES.MODE_CBC, init_vector_r)
    decrypted_data = aes_cbc_decrypt.decrypt((ike_auth_r[IKEv2_payload_Encrypted].load)[:-12])
# ikev2_payload_decrypted = IKEv2_payload_Decrypted(next_payload=IKEv2_payload_type.index('IDi'))
# ikev2_payload_decrypted /= decrypted_data


ikev2_payload_decrypted = dissert_ikev2_decrypted_payload("IDi", decrypted_data)
# ikev2.show2()
# ikev2[IKEv2_payload_AUTH].show2()
print "line %d: ipsec_spi_r is %s" %(lineno(), toHex(ikev2_payload_decrypted[IKEv2_payload_Proposal].SPI))
# ikev2_payload_decrypted.show2()

# ike_auth_r.show2()
ipsec_spi_r = ikev2_payload_decrypted[IKEv2_payload_Proposal].SPI
break
'''

conf.setkey.add('IPV4','*','192.168.*.42','6','ESP','AES-CBC', '1234abc12ffffbc1', 'HMAC-SHA256-96' ,'5llll632abc1azefvc')