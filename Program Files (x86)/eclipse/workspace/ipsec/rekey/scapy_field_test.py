ENCRYPTION_MODE = "AES-CBC"
var = 100

import inspect
from scapy.all import *

print var

def lineno():
    return inspect.currentframe().f_back.f_lineno


def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0' + hv
        lst.append(hv)

    return reduce(lambda x, y: x + y, lst)

#convert hex repr to string
def toStr(s):
    return s and chr(string.atoi(s[:2], base=16)) + toStr(s[2:]) or ''

'''
class TestSLF(Packet):
    fields_desc=[ FieldLenField("len", None, length_of="data"),
                  StrLenField("data", "", length_from=lambda pkt:pkt.len) ]

class TestPLF(Packet):
    fields_desc=[ FieldLenField("len", None, count_of="plist"),
                  PacketListField("plist", None, IP, count_from=lambda pkt:pkt.len) ]

class TestFLF(Packet):
    fields_desc=[
       FieldLenField("the_lenfield", None, count_of="the_varfield"),
       FieldListField("the_varfield", ["1.2.3.4"], IPField("", "0.0.0.0"),
                       count_from = lambda pkt: pkt.the_lenfield) ]

class TestPkt(Packet):
    fields_desc = [ ByteField("f1",65),
                    ShortField("f2",0x4244) ]
    def extract_padding(self, p):
        return "", p

class TestPLF2(Packet):
    fields_desc = [ FieldLenField("len1", None, count_of="plist",fmt="H", adjust=lambda pkt,x:x+2),
                    FieldLenField("len2", None, length_of="plist",fmt="I", adjust=lambda pkt,x:(x+1)/2),
                    PacketListField("plist", None, TestPkt, length_from=lambda x:(x.len2*2)/3*3) ]

class test_payload_Delete(Packet):
    name = "test_payload_Delete"
    fields_desc = [
        ByteField("next_payload",0x01),
        ByteField("res",0),
        FieldLenField("length", None, fmt="H", length_of="spi_index", adjust=lambda pkt,l:l+8),
        ByteField("protocol_id", 1),
        ByteField("spi_size", 0),
        ShortField("spi_num", 0),
        ConditionalField(FieldListField("spi_index", ["aaaa"], StrFixedLenField("", "bbbb", length=4), count_from=lambda pkt:pkt.spi_num), lambda pkt:pkt.spi_num > 0)
        # ConditionalField(StrLenField("spi_index", "", length_from=lambda pkt:pkt.spi_num*4), lambda pkt:pkt.spi_num > 0)
        ]
       
        
# a = test_payload_Delete(spi_num = 2, spi_index = ['cccc', 'dddd'])
a = test_payload_Delete(spi_num = 1, spi_index = toStr('41414141'))
a.show2()

print (a.spi_index)

b = test_payload_Delete(str(a))
b.show2()
print toHex(str(a))
        
        
TestFLF("\x00\x02ABCDEFGHIJKL").show2()

a = TestFLF(the_varfield = ['1.1.1.1', '2.2.2.2', '3.3.3.3'])
print toHex(str(a))
'''

'''
class IKEv2_class(Packet):
    def guess_payload_class(self, payload):
        # print sys._getframe().f_code.co_filename + " : " + sys._getframe().f_code.co_name + " : " + str(sys._getframe().f_lineno)
        np = self.next_payload
        logging.debug("For IKEv2_class np=%d" % np)
        if np == 0:
            return Raw
        elif np < len(IKEv2_payload_type):
            pt = IKEv2_payload_type[np]
            logging.debug(globals().get("IKEv2_payload_%s" % pt, IKEv2_payload))
            return globals().get("IKEv2_payload_%s" % pt, IKEv2_payload)
        else:
            return IKEv2_payload

class IKEv2_payload_Encrypted(IKEv2_class):
    name = "IKEv2 Encrypted and Authenticated"
    encrypt_mode = "3DES"
    overload_fields = { IKEv2: { "next_payload":46 }}

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
        if self.encrypt_mode == "3DES":
            fields_desc = [
                ByteEnumField("next_payload",None,IKEv2_payload_type),
                ByteField("res",0),
                FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+12),
                #'Q' represents 8Bytes
                StrLenField('iv', "", 8),
                StrLenField("load","",length_from=lambda x:x.length-12),
                ]
        elif self.encrypt_mode == "AES_CBC":
             fields_desc = [
                ByteEnumField("next_payload",None,IKEv2_payload_type),
                ByteField("res",0),
                FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+20),
                #'Q' represents 8Bytes
                StrLenField('iv', "", 16),
                StrLenField("load","",length_from=lambda x:x.length-20),
                ]
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

IKEv2_payload_Encrypted.encrypt_mode = "AES_CBC"
ikev2_payload_encrypted = IKEv2_payload_Encrypted()
ikev2_payload_encrypted.show2()
'''

class test_Key_Length_Attribute(IntField):
    # We only support the fixed-length Key Length attribute (the only one currently defined)
    name="key length"
    def __init__(self, name):
#        IntField.__init__(self, name, "0x800E0000")
        IntField.__init__(self, name, 0x800E0000)
    def i2h(self, pkt, x):
        return IntField.i2h(self, pkt, x & 0xFFFF)

    def h2i(self, pkt, x):
#        value = toHex(struct.pack("!I", 0x800E0000 | int(x, 0)))
#        value = toHex(struct.pack("!I", 0x800E0000 | x))
        value = toHex(struct.pack("!I", 0x800E0000 | x))
#        a = IntField.h2i(self, pkt, value)
        a = IntField.h2i(self, pkt, 0x800e0080)
#        return IntField.h2i(self, pkt, value)
        return a
    def i2m(self, pkt, x):
        """Convert internal value to machine value"""
        if x is None:
            x = 0
        return x
    
    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        a = toHex(s)
        b = self.i2m(pkt,val)
#        c = struct.pack(self.fmt, int(b,16))
        c = struct.pack(self.fmt, b)
        d = s+c
        return d

#class test_payload_Transform(IKEv2_class):
#    name = "IKE Transform"
#    fields_desc = [
#        ByteEnumField("next_payload",None,{0:"last", 3:"Transform"}),
#        ByteField("res",0),
#        ShortField("length",8),
#        ByteEnumField("transform_type",None,IKEv2Transforms),
#        ByteField("res2",0),
#        IKEv2_Transform_ID("transform_id", 3),
#        ConditionalField(test_Key_Length_Attribute("key_length"), lambda pkt: pkt.length > 8),
#        # StrLenField("key_length","",length_from=lambda pkt:pkt.length-8),
#    ]
#    
#    def post_build(self, p, pay):
#        p += pay
#        p = p[:2] + struct.pack("!H", len(p)) + p[4:]
#        return p

#test_payload_transform = test_payload_Transform(next_payload = 0, key_length = 128)
#d = str(test_payload_transform)
##test_payload_transform.show2()
#hexdump(test_payload_transform)

#test_key_length_attribute = test_Key_Length_Attribute("128")

ikev2_payload_encrypted = IKEv2_payload_Encrypted()
ikev2_payload_encrypted.next_payload = IKEv2_payload_type.index('IDi')  #next payload is Identification - Initiator
ikev2_payload_encrypted.res  = 0x00         #reserved
ikev2_payload_encrypted.iv   = ''.join(RandString(16))  #initialation vector  
ikev2_payload_encrypted.show2()

