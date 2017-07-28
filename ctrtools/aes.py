from Crypto.Cipher import AES
from . import ctrkeys
from . import aes
from .otp import OTP
import hashlib
import io

def asint128(a):
    return a & (2**128-1)

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
    def __int__(self):
        return self.key

    def __add__(self, other):
        if isinstance(other, int):
            return self + AESKey(other)
        return AESKey(self.key + other.key, self.twl)
    def __sub__(self, other):
        if self.key < other.key:
            return AESKey((self.key+2**128)-other.key, self.twl)
        return AESKey(self.key-other.key, self.twl)
    def __or__(self, other):
        return AESKey(self.key | other.key, self.twl)
    def __xor__(self, other):
        return AESKey(self.key ^ other.key, self.twl)
    def __lshift__(self, other):
        return AESKey(self.key<<other, self.twl)
    def __rshift__(self, other):
        return AESKey(self.key>>other, self.twl)
    def reverse(self):
        return AESKey(bytes(self)[::-1], self.twl)
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

def representAESKey(dumper, data):
    return dumper.represent_int(hex(data.key))
ctrkeys.yaml.add_representer(AESKey, representAESKey)


class Keyslots:
    def __init__(self):
        if not "b9 common" in ctrkeys.ctrkeys["contents"]:
            Keyslots.getCommon()
        if not "b9 conunique" in ctrkeys.ctrkeys["contents"]:
            Keyslots.getUnique()
        self.keyX={}
        self.keyY={}
        self.keys={}
        for no, keyslot in ctrkeys.ctrkeys["keyslots"].items():
            if "N" in keyslot:
                self.setKey(no, keyslot["N"])
            if "X" in keyslot:
                self.setKeyX(no, keyslot["X"])
            if "Y" in keyslot:
                self.setKeyY(no, keyslot["Y"])
        self.save()
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
                                ctrkeys.ctrkeys["keyslots"][kn][type] = AESKey(boot9.read(16))
                            else:
                                ctrkeys.ctrkeys["keyslots"][kn] = {type:AESKey(boot9.read(16))}
                    else:
                        key = int(AESKey(boot9.read(16)))
                        for i in range(4):
                            kn = start + i
                            if kn in ctrkeys.ctrkeys["keyslots"]:
                                ctrkeys.ctrkeys["keyslots"][kn][type] = key
                            else:
                                ctrkeys.ctrkeys["keyslots"][kn] = {type: key}
                    if not increase_after:
                        boot9.seek(o)

                boot9.seek(0xD6E0)
                ctrkeys.ctrkeys["otp"] = {
                        "key":int(AESKey(boot9.read(16))),
                        "iv":int(AESKey(boot9.read(16)))}

        except:
            raise ValueError("Could not read the bootrom for the common keys")
        ctrkeys.ctrkeys["contents"].append("b9 common")
        ctrkeys.savekeys()
    @staticmethod
    def getUnique():
        otp = OTP()
        try:
            with open("data/boot9.bin", "rb") as boot9:
                boot9.seek(0xD860)
                _3fgendata = boot9.read(0x24)
                boot9.seek(0xD860)
                h = hashlib.sha256(otp.decrypted[:28] + _3fgendata).digest()
                ctrkeys.ctrkeys["keyslots"][0x3F] = {
                        "X": AESKey(h[:16]),
                        "Y": AESKey(h[16:])
                        }
                ctrkeys.ctrkeys["keyslots"][0x3F]['N'] = AESKey.scramble_ctr(AESKey(h[:16]), AESKey(h[16:]))
                keys = [
                        (64,
                         (0x04, 'X', False, False),
                         (0x08, 'X', False, False),
                         (0x0C, 'X', False, False),
                         (0x10, 'X', False, True),
                        ),
                        (16,
                         (0x14, 'X', True, False),
                        ),
                        (64,
                         (0x18, 'X', False, False),
                         (0x1C, 'X', False, False),
                         (0x20, 'X', False, False),
                         (0x24, 'X', False, True),
                        ),
                        (16,
                         (0x28, 'X', True, False),
                        ),
                    ]
                def setKey(slot, type, val):
                    if slot in ctrkeys.ctrkeys["keyslots"]:
                        ctrkeys.ctrkeys["keyslots"][slot][type] = val
                    else:
                        ctrkeys.ctrkeys["keyslots"][slot] = {type:val}
                for group in keys:
                    dataLength = group[0]
                    boot9.read(36)
                    aesiv = boot9.read(16)
                    o = boot9.tell()
                    conunique = boot9.read(64)
                    boot9.seek(o+dataLength)
                    keydata = io.BytesIO(ctrkeys.ctrkeys["keyslots"][0x3F]['N'].encrypt("cbc", conunique, aesiv))
                    for keyslot, keytype, increasing, single in group[1:]:
                        if single:
                            setKey(keyslot, keytype, AESKey(keydata.read(16)))
                        else:
                            if increasing:
                                for i in range(4):
                                    setKey(keyslot+i, keytype, AESKey(keydata.read(16)))
                            else:
                                key = AESKey(keydata.read(16))
                                for i in range(4):
                                    setKey(keyslot+i, keytype, key)
        except:
            raise ValueError("Could not read the bootrom for the console unique keys")
        ctrkeys.ctrkeys["contents"].append("b9 conunique")
        ctrkeys.savekeys()
    def setKeyX(self, keyno, key):
        twl = False
        if keyno <= 4:
            twl = True
        if isinstance(key, int):
            self.keyX[keyno]=AESKey(key, twl)
        else:
            self.keyX[keyno]=key
    def setKeyY(self, keyno, key):
        twl = False
        if keyno <= 4:
            twl = True
        if isinstance(key, int):
            self.keyY[keyno]=AESKey(key, twl)
        else:
            self.keyY[keyno]=key
        if keyno <= 4:
            self.keys[keyno] = AESKey.scramble_twl(self.keyX[keyno], self.keyY[keyno])
        else:
            self.keys[keyno] = AESKey.scramble_ctr(self.keyX[keyno], self.keyY[keyno])
    def setKey(self, keyno, key):
        twl = False
        if keyno <= 4:
            twl = True
        if isinstance(key, int):
            self.keys[keyno]=AESKey(key, twl)
        else:
            self.keys[keyno]=key
    def save(self):
        for k,v in self.keyX.items():
            ctrkeys.ctrkeys["keyslots"][k] = {"X": v}
        for k,v in self.keyY.items():
            if k in self.keyX:
                ctrkeys.ctrkeys["keyslots"][k]["Y"] = v
            else:
                ctrkeys.ctrkeys["keyslots"][k] = {"Y":v}
        for k,v in self.keys.items():
            if (k in self.keyX) or (k in self.keyY):
                ctrkeys.ctrkeys["keyslots"][k]["N"] = v
            else:
                ctrkeys.ctrkeys["keyslots"][k] = {"N":v}
        ctrkeys.savekeys()
