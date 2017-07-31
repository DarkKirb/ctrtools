import struct
from . import common
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
        return common.BoundedReader(self.f, self.files[fname][0]+self.off+0x200, self.files[fname][1])


