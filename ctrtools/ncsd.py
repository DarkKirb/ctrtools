import struct
from . import ctrkeys
from . import aes
from . import exefs
import hashlib
class NCSD(object):
    def __new__(cls, f):
        if cls is NCSD:
            o = f.tell()
            f.read(0x108)
            x = f.read(8)
            f.seek(o)
            if int.from_bytes(x,'little') == 0:
                return super().__new__(NCSD_NAND)
            else:
                return super().__new__(NCSD_CCI)
        else:
            return super().__new__(cls)

    def __init__(self, f):
        self.f=f
        self.off=f.tell()
        f.read(0x100)
        assert f.read(4) == b"NCSD"
        self.size, self.mediaID = struct.unpack("<IQ",f.read(12))
        fstype=struct.unpack("<BBBBBBBB",f.read(8))
        crypttype=struct.unpack("<BBBBBBBB",f.read(8))
        parttable=[]
        for i in range(8):
            parttable.append(struct.unpack("<II", f.read(8)))
        self.partitions={}
        for i in range(8):
            if parttable[i][1] == 0:
                break
            self.partitions[i]=(fstype[i], crypttype[i], self.off+parttable[i][0]*512, parttable[i][1]*512)

    def open(self, partID):
        if not partID in self.partitions:
            raise FileNotFoundError("Could not find NCSD Partition {}!".format(partID))
        return NCSD_Part(self.f, *self.partitions[partID])

class NCSD_NAND(NCSD):
    def __init__(self, f):
        super().__init__(f)
        #TODO add MBR decryption code here

class NCSD_CCI(NCSD):
    def __init__(self, f):
        super().__init__(f)
        f.read(0x20)
        self.additionalHeaderSize, self.zeroSectorOff = struct.unpack("<II", f.read(8))
        self.backupWaitTime, self.cardType, self.mediaPlatform, self.typeIndex, self.mediaUnitSize, self.cardDeviceOld = struct.unpack("<BxxBBBBB", f.read(8))

class NCSD_Part(object):
    def __new__(cls, *args):
        if cls is NCSD_Part:
            f,fstype,cryptotype,off,size=args
            keyslots= [
                    [ 0,0,0,0 ],
                    [ 0,3,4,5 ],
                    [ 0,3,4,5 ],
                    [ 0,0,6,0 ],
                    [ 0,0,7,0 ],
                    [ 0,0,0,0 ],
                    [ 0,0,0,0 ],
                    [ 0,0,0,17 ],
                    [ 0,0,0,0 ]]
            if not keyslots[fstype][cryptotype]:
                return NCSD_Unencrypted(*args)
            else:
                return NCSD_Encrypted(*args)
        else:
            return super().__new__(cls)
    def __init__(self, *args):
        pass
    def read(self, length=None):
        o=self.f.tell()
        if length is None or length > self.size - self.pos:
            length = self.size - self.pos
        data = b''
        if self.pos & 0xF:
            self.f.seek(self.off + (self.pos & 0xFFFFFFF0))
            trailer = self.f.read(16)
            data += self.decrypt(self, self.pos & 0xFFFFFFF0, trailer)[16-(self.pos&0xF):length+16-(self.pos&0xF)]
            self.pos += len(data)
            length -= len(data)
        if not length:
            return data
        data+= self.decrypt(self.pos, self.f.read(length & 0xFFFFFFF0))
        self.pos += length & 0xFFFFFFF0
        length &= 0xF
        if length:
            data+=self.decrypt(self.pos, self.f.read(16))[:length]
        return data
    def tell(self):
        return self.pos
    def seek(self, pos):
        self.pos = pos


class NCSD_Unencrypted(NCSD_Part):
    def __init__(self, f, fstype, cryptotype, off, size, *args):
        self.f = f
        self.off = off
        self.size = size
        self.pos=0
    def decrypt(self, pos, data):
        return data

class NCSD_Encrypted(NCSD_Part):
    def __init__(self, f, fstype, cryptotype, off, size, *args):
        keyslots= [
                    [ 0,0,0,0 ],
                    [ 0,3,4,5 ],
                    [ 0,3,4,5 ],
                    [ 0,0,6,0 ],
                    [ 0,0,7,0 ],
                    [ 0,0,0,0 ],
                    [ 0,0,0,0 ],
                    [ 0,0,0,17 ],
                    [ 0,0,0,0 ]]
        keyslot = keyslots[fstype][cryptotype]
        self.f = f
        self.keyslot = keyslot
        self.off = off
        self.size = size
        self.pos=0
        self.keys = aes.Keyslots()
        if keyslot == 0x11:
            with open("data/otp.bin", "rb") as f:
                h = hashlib.sha256(f.read()).digest()
                self.keys.setKeyX(0x11, aes.AESKey(h[:16]))
                self.keys.setKeyY(0x11, aes.AESKey(h[16:]))
                self.keys.save()
        if keyslot == 0x05:
            #N3DS ctrnand has a different keyY than was set by boot9. No way to get it, because we need this key to access process9
            #Keyslot 0x05 is unuses on o3ds iirc
            self.keys.setKeyY(0x05, aes.AESKey(0x4D804F4E9990194613A204AC584460BE))
            self.keys.save()
        if keyslot < 0x08:
            if not "nand" in ctrkeys.ctrkeys["contents"]:
                nand = open("data/nand.bin","rb")
                nand.seek(0x200)
                fs = exefs.ExeFS(nand)
                cidFile = fs.open("nand_cid")
                cid = cidFile.read(16)
                ctriv = hashlib.sha256(cid).digest()[:16]
                twliv = hashlib.sha1(cid).digest()[:16] #TODO because I know TWL there might be some transformations like swapping endian
                ctrkeys.ctrkeys["nand"] = {
                    "cid":cid,
                    "iv":{"ctr":aes.AESKey(ctriv), "twl":aes.AESKey(twliv, True)}
                        }
                ctrkeys.ctrkeys["contents"].append("nand")
                self.keys.save()
    def decrypt(self, pos, data):
        if self.keyslot <= 4:
            return self.keys.keys[self.keyslot].decrypt("ctr", data, int(ctrkeys.ctrkeys["nand"]["iv"]["twl"]+pos//16))
        else:
            return self.keys.keys[self.keyslot].decrypt("ctr", data, int(ctrkeys.ctrkeys["nand"]["iv"]["ctr"]+pos//16))
