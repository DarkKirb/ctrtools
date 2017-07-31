from ctrtools import ncsd
n=ncsd.NCSD(open("data/nand.bin","rb"))
ctrnand=n.open(4)
from ctrtools import mbr
ctrnand_mbr=mbr.MBR(ctrnand)
ctrnand_part=ctrnand_mbr.open(0)
from ctrtools import fat
f=fat.FAT(ctrnand_part)
print(f.open_dir("/σitle"))

