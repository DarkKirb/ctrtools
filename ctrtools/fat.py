import struct

class FAT:
    def __init__(self, f):
        self.f=f
        self.off=f.tell()
        f.read(3)
        self.oemident = f.read(8)
        self.bytes_per_sector, self.sectors_per_cluster, self.reserved_sectors, self.num_FAT, self.root_dirents, self.short_seccount, self.sec_per_FAT, self.sec_per_track, self.no_heads, self.hidden_sec_count, self.seccount = struct.unpack("<HBHBHHxHHHII",f.read(25))
        self.bytes_per_cluster = self.bytes_per_sector * self.sectors_per_cluster
        f.read(7)
        self.vollabel=f.read(11)
        self.sysident=f.read(8)
        self.root_dir_sectors = ((self.root_dirents*32) + (self.bytes_per_sector - 1)) // self.bytes_per_sector
        self.first_data_sector = self.reserved_sectors + (self.num_FAT * self.sec_per_FAT) + self.root_dir_sectors
        f.seek(self.reserved_sectors * self.bytes_per_sector)
        fat_buf = f.read(self.sec_per_FAT * self.bytes_per_sector)
        fat=[]
        for i in range(len(fat_buf)//2):
            fat.append(int.from_bytes(fat_buf[2*i:2*(i+1)],'little'))
        self.fat=fat

    def traverse_cluster_chain(self, start):
        print(start)
        yield start
        curr=start
        while self.fat[curr] < 0xFFF7:
            curr=self.fat[curr]
            print(curr)
            yield curr
    def read_cluster(self, cluster):
        self.f.seek((self.first_data_sector + (cluster-2) * self.sectors_per_cluster) * self.bytes_per_sector)
        return self.f.read(self.bytes_per_cluster)

    def read_root_dir(self):
        self.f.seek((self.reserved_sectors + (self.num_FAT * self.sec_per_FAT)) * self.bytes_per_sector)
        return self.f.read(self.root_dir_sectors * self.bytes_per_sector)

    def open_dir(self, fname):
        rootdir=b''
        if fname == "/":
            rootdir=self.read_root_dir()
        else:
            pdname = fname.rsplit("/", 1)[0]
            cwdname = fname.rsplit("/", 1)[1]
            if pdname == "":
                pdname="/"
            pdents = self.open_dir(pdname)
            for fname, isdir, startcluster, length in pdents:
                if fname != cwdname:
                    continue
                if not isdir:
                    raise IOError("{} is not a directory".format(fname))
                for cluster in self.traverse_cluster_chain(startcluster):
                    rootdir+=self.read_cluster(cluster)
                break
            if rootdir==b"":
                raise FileNotFoundError("{}/{}: No such directory".format(pdname, cwdname))

        ents=[]
        current_lfn={}
        for i in range(len(rootdir)//32):
            ent = rootdir[32*i:32*(i+1)]
            if ent[0] == 0xE5:
                continue #Ignore this entry
            if ent == bytes(32):
                break
            fname = ent[0:8].decode("cp437").rstrip().lower() + "." + ent[8:11].decode("cp437").rstrip().lower()
            if fname[-1] == ".":
                fname = fname[:-1]
            if ent[11] == 0xF:
                lfn_part = ent[1:11] + ent[14:26] + ent[28:]
                index = ent[0]
                current_lfn[ent[0]&0x3F] = lfn_part.decode("UTF-16LE")

                continue
            if current_lfn != {}:
                lfn_str=""
                for k in sorted(current_lfn.keys()):
                    lfn_str+=current_lfn[k]
                fname = lfn_str.rstrip("\uFFFF\0")
                current_lfn={}

            isdir = ent[11] & 0x10
            startcluster = int.from_bytes(ent[26:28], 'little')
            length = int.from_bytes(ent[28:], 'little')
            ents.append((fname, isdir, startcluster, length))

        return ents
    def open(self, fname):
        pdname = fname.rsplit("/", 1)[0]
        basename = fname.rsplit("/", 1)[1]
        if pdname == "":
            pdname = "/"
        pdents = self.open_dir(pdname)
        for fname, isdir, startcluster, length in pdents:
            if fname != basename:
                continue
            if isdir:
                raise IOError("{} is a directory".format(fname))
            return FATReader(self, startcluster, length)
        raise FileNotFoundError("{}/{}: No such file".format(pdname, basename))

class FATReader:
    def __init__(self, fat, startcluster, length):
        self.fat=fat
        self.startcluster=startcluster
        self.length=length
        self.off=0
    def read(self, length=None):
        if length is None or length > self.length - self.off:
            length = self.length - self.off
        data=b""
        #Step 1: Seek to the first cluster of the data
        clusteroff = self.off
        cluster = self.startcluster
        while clusteroff >= self.fat.bytes_per_cluster:
            clusteroff -= self.fat.bytes_per_cluster
            cluster = self.fat.fat[cluster]
        #Step 2: read the firstt partial cluster
        if self.off & (self.fat.bytes_per_cluster - 1):
            head_part = self.fat.read_cluster(cluster)
            data += head_part[clusteroff:clusteroff+length]
            clusteroff = 0
            cluster = self.fat.fat[cluster]
            self.off+=len(data)
            length -= len(data)

        while length >= self.fat.bytes_per_cluster:
            data+=self.fat.read_cluster(cluster)
            cluster = self.fat.fat[cluster]
            length -= self.fat.bytes_per_cluster
            self.off+=self.fat.bytes_per_cluster

        if length:
            data+=self.fat.read_cluster(cluster)[:length]
            self.off+=length
        return data
    def tell():
        return self.off
    def seek(off):
        self.off=off
