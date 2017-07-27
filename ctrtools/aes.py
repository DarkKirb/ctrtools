from Crypto.Cipher import AES
from . import ctrkeys

def asint128(a):
    return a & (1**128-1)

class AESKey(object):
    def __init__(self, key, twl=False):
        if isinstance(key, bytes):
            self.key = int.from_bytes(key, 'big')
        else:
            self.key = key
        self.key=asint128(self.key)
        self.twl=twl
    def __repr__(self):
        return hex(self.key)
    def __str__(self):
        return repr(self)
    def __bytes__(self):
        return self.key.to_bytes(16, 'big')

    def __add__(self, other):
        return AESKey(self.key - other.key)
    def __sub__(self, other):
        if self.key < other.key:
            return AESKey((self.key+2**128)-other.key)
        return AESKey(self.key-other.key)
    def __or__(self, other):
        return AESKey(self.key | other.key)
    def __xor__(self, other):
        return AESKey(self.key ^ other.key)
    def __lshift__(self, other):
        return AESKey(self.key<<other)
    def __rshift__(self, other):
        return AESKey(self,key>>other)
    def reverse(self):
        return AESKey(bytes(self)[::-1])
    @staticmethod
    def scramble_ctr(keyX, keyY):
        rotate = lambda c,v: (c << v) | (c >> (128-v))
        return rotate((rotate(keyX, 2)^keyY)+ctrkeys.ctrkeys["keyscrambler"]["ctr"], 87)
    @staticmethod
    def scramble_twl(keyX, keyY):
        rotate = lambda c,v: (c << v) | (c >> (128-v))
        keyXY = keyX.reverse() ^ keyY.reverse()
        return rotate(keyXY+ctrkeys.ctrkeys["keyscrambler"]["twl"], 42).reverse()

    def encrypt(self, mode, data, iv=None):
        cipher = None
        if mode == "ecb":
            cipher = AES.new(bytes(self), AES.MODE_ECB)
        elif mode == "cbc":
            cipher = AES.new(bytes(self), AES.MODE_CBC, iv)
        elif mode == "ctr":
            cipher = AES.new(bytes(self), AES.MODE_CTR, iv)
        else:
            raise ValueError("Unknown mode {}!".format(mode))

        if self.twl and mode == "ctr":
            #Create Pad
            pad = cipher.encrypt(bytes(len(data)))
            encrypted=b''
            #Encrypt
            for i in range(0, len(data), 16):
                encrypted += (int.from_bytes(pad[i:i+16],'little') ^ int.from_bytes(data[i:i+16], 'big')).to_bytes(16, 'big')
            return encrypted

        return cipher.encrypt(data)
    def decrypt(self, mode, data, iv=None):
        cipher = None
        if mode == "ecb":
            cipher = AES.new(bytes(self), AES.MODE_ECB)
        elif mode == "cbc":
            cipher = AES.new(bytes(self), AES.MODE_CBC, iv)
        elif mode == "ctr":
            return self.encrypt(mode, data, iv)
        else:
            raise ValueError("Unknown mode {}!".format(mode))

        return cipher.decrypt(data)

class Keyslots:
    def __init__(self):
        if not "b9 common" in ctrkeys.ctrkeys["contents"]:
            Keyslots.getCommon()
    @staticmethod
    def getCommon():
        try:
            with open("data/boot9.bin", "rb") as boot9:
                ctrkeys.ctrkeys["keyslots"] = {}
                boot9.seek(0xD860)
                boot9.read(0x170)
                keys=[(0x2C, 'X', False, True),
                      (0x30, 'X', False, True),
                      (0x34, 'X', False, True),
                      (0x38, 'X', False, True),
                      (0x3C, 'X', True, True),
                      (0x04, 'Y', True, True),
                      (0x08, 'Y', True, True),
                      (0x0C, 'N', False, True),
                      (0x10, 'N', False, True),
                      (0x14, 'N', True, True),
                      (0x18, 'N', False, True),
                      (0x1C, 'N', False, True),
                      (0x20, 'N', False, True),
                      (0x24, 'N', False, False),
                      (0x28, 'N', True, True),
                      (0x2C, 'N', False, True),
                      (0x30, 'N', False, True),
                      (0x34, 'N', False, True),
                      (0x38, 'N', False, False),
                      (0x3C, 'N', False, True)]
                for start, type, different, increase_after in keys:
                    o=boot9.tell()
                    if different:
                        for i in range(4):
                            kn = start + i
                            if kn in ctrkeys.ctrkeys["keyslots"]:
                                ctrkeys.ctrkeys["keyslots"][kn][type] = int.from_bytes(boot9.read(16),"big")
                            else:
                                ctrkeys.ctrkeys["keyslots"][kn] = {type:int.from_bytes(boot9.read(16),'big')}
                    else:
                        key = int.from_bytes(boot9.read(16), 'big')
                        for i in range(4):
                            kn = start + i
                            if kn in ctrkeys.ctrkeys["keyslots"]:
                                ctrkeys.ctrkeys["keyslots"][kn][type] = key
                            else:
                                ctrkeys.ctrkeys["keyslots"][kn] = {type: key}
                    if not increase_after:
                        boot9.seek(o)

        except:
            raise ValueError("Could not read the bootrom for the common keys")
        ctrkeys.ctrkeys["contents"].append("b9 common")
        ctrkeys.savekeys()
