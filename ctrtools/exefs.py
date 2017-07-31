import struct
class ExeFS:
    def __init__(self, f):
        self.f = f
        self.off = f.tell()
        self.files={}
        for i in range(10):
            fname = f.read(8)
            offset, size = struct.unpack("<II", f.read(8))
            if size == 0:
                break
            self.files[fname.decode("UTF-8").rstrip('\0')] = (offset, size)
    def open(self, fname):
        if not fname in self.files:
            raise FileNotFoundError("Could not find file {}!".format(fname))
        return ExeFSFile(self.f, self.files[fname][0]+self.off+0x200, self.files[fname][1])


class ExeFSFile:
    def __init__(self, f, off, size):
        self.f=f
        self.off=off
        self.size=size
        self.pos=0
    def read(self, size=None):
        o=self.f.tell()
        self.f.seek(self.off+self.pos)
        if size is None or size > self.size - self.pos:
            data=self.f.read(self.size - self.pos)
            self.pos = self.size
        else:
            data=self.f.read(size)
            self.pos += size
        self.f.seek(o)
        return data
    def tell(self):
        return self.pos
    def seek(self, pos):
        self.pos = pos
