class BoundedReader:
    def __init__(self, f, off, size):
        self.f=f
        self.off=off
        self.size=size
        self.pos=0
    def read(self, size=None):
        o=self.f.tell()
        self.f.seek(self.off+self.pos)
        if size is None or size > self.size - self.pos:
            data = self.f.read(self.size - self.pos)
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
