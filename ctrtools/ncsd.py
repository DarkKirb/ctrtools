import struct
class NCSD(object):
    def __init__(self, f):
        self.begin = f.tell()
        self.f = f
        f.read(256) #Skip the sig
        if f.read(4) != b'NCSD':
            raise ValueError("This is not a valid NCSD image")
        self.size, self.mediaID = struct.unpack("<IQ", f.read(12))
        self.parts=[]
        for i in  range(8):
            f.seek(self.begin+0x110+i)
            fstype = int(f.read(1))
            f.seek(self.begin+0x118+i)
            fscrypto = int(f.read(1))
            f.seek(self.begin+0x120+i*8)
            off,length = struct.unpack("<II",f.read(8))
            if not fstype:
                break
            self.parts.append(NCSDPart(self, fstype, fscrypto, off, length))
    def seek(self, off):
        f.seek(self.begin+off)
    def tell(self):
        return f.tell() - self.begin
    def read(self, length):
        return f.read()
class NCSDPart(object):
    def __init__(self, f, fstype, fscrypto, off, length):
        self.f = f
        self.fstype = fstype
        self.fscrypto = fscrypt

