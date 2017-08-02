import struct
from . import common
class MBR:
    def __init__(self, f):
        self.f = f
        self.off = f.tell()
        f.seek(0x1FE)
        assert f.read(2) == b'\x55\xaa'
        f.seek(0x1BE)
        parts={}
        for i in range(4):
            f.read(4)
            parttype, start, length = struct.unpack("<BxxxII", f.read(12))
            if parttype == 0:
                continue
            parts[i] = (start, length)
        self.parts=parts
    def open(self, partid):
        if not partid in self.parts:
            raise FileNotFoundError("Could not find partition {}!".format(partid))
        return common.BoundedReader(self.f, self.parts[partid][0]*512 + self.off, self.parts[partid][1]*512)
    def open_dir(self, fname):
        parts=[]
        for partid, start, length in self.parts.items():
            parts.append((partid,start,length))
        return parts
