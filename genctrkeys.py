#!/usr/bin/env python3
import yaml
import hashlib
import os
import io
def hexint_presenter(dumper, data):
    return dumper.represent_int(hex(data))
yaml.add_representer(int, hexint_presenter)


ctrkeys={
        "keyscrambler-const":0x1FF9E9AAC5FE0408024591DC5D52768A
        } #Hardcoded. This value cannot be found out without hardcoding a keyX keyY NKey pair.

def scramble(keyX, keyY):
    def asint128(a):
        assert a>=0
        return a & ((2**128)-1)
    rotate = lambda c,v: (asint128(c<<v) | (asint128(c>>(128-v))))
    return rotate((rotate(keyX,2) ^ keyY) + ctrkeys["keyscrambler-const"], 87)


def isN3DS():
    return os.path.getsize("data/nand_minsize.bin") >= 1300234240 #N3DS nand size

def isDev3DS():
    value=None
    while value is None:
        try:
            value = int(input("Is this 3DS a development unit? (1 == yes) "))
        except:
            pass
    return True if value else False

ctrkeys["isN3DS"] = isN3DS()
ctrkeys["isDev3DS"] = isDev3DS()
boot9keys={}

print("Dumping the AES keys from boot9.bin")
def keys(f, k, t):
    key = int.from_bytes(f.read(16), 'big')
    for i in range(k,k+4):
        if i not in boot9keys:
            boot9keys[i] = {t:key}
        else:
            boot9keys[i][t] = key

def keys_inc(f, k, t):
    for i in range(k,k+4):
        key = int.from_bytes(f.read(16), 'big')
        if i not in boot9keys:
            boot9keys[i] = {t:key}
        else:
            boot9keys[i][t] = key
with open("data/boot9.bin", "rb") as boot9:
    if ctrkeys["isDev3DS"]:
        boot9.seek(0xDC60)
    else:
        boot9.seek(0xD860)
    _3fgendata=boot9.read(0x24)
    boot9.read(0x14C) #Skip over currently useless data
    keys(boot9, 0x2C, 'X')
    keys(boot9, 0x30, 'X')
    keys(boot9, 0x34, 'X')
    keys(boot9, 0x38, 'X')
    keys_inc(boot9, 0x3C, 'X')
    keys_inc(boot9, 0x04, 'Y')
    keys_inc(boot9, 0x08, 'Y')
    keys(boot9, 0x0C, 'N')
    keys(boot9, 0x10, 'N')
    keys_inc(boot9, 0x14, 'N')
    keys(boot9, 0x18, 'N')
    keys(boot9, 0x1C, 'N')
    keys(boot9, 0x20, 'N')
    o = boot9.tell()
    keys(boot9, 0x24, 'N')
    boot9.seek(o)
    keys_inc(boot9, 0x28, 'N')
    keys(boot9, 0x2C, 'N')
    keys(boot9, 0x30, 'N')
    keys(boot9, 0x34, 'N')
    o = boot9.tell()
    keys(boot9, 0x38, 'N')
    boot9.seek(o)
    keys(boot9, 0x3C, 'N')
    if ctrkeys["isDev3DS"]:
        boot9.seek(0xD700)
    else:
        boot9.seek(0xD6E0)
    ctrkeys["otp"] = {"key":int.from_bytes(boot9.read(16), 'big')}
    ctrkeys["otp"]["iv"] = int.from_bytes(boot9.read(16), 'big')

ctrkeys["defaultKeyslots"] = boot9keys

print("Generating 0x3F Key X, Y and N")

from Crypto.Cipher import AES
import base64
with open("data/otp.mem", "rb") as otp:
    ctrkeys["otp"]["decrypted"] = AES.new(ctrkeys["otp"]["key"].to_bytes(16, 'big'), AES.MODE_CBC, ctrkeys["otp"]["iv"].to_bytes(16, 'big')).decrypt(otp.read())

conunique=ctrkeys["otp"]["decrypted"][:28] + _3fgendata
conunique_hash = hashlib.sha256(conunique).digest()

ctrkeys["defaultKeyslots"][0x3F]['X'] = int.from_bytes(conunique_hash[:16], 'big')
ctrkeys["defaultKeyslots"][0x3F]['Y'] = int.from_bytes(conunique_hash[16:], 'big')
ctrkeys["defaultKeyslots"][0x3F]['N'] = scramble(ctrkeys["defaultKeyslots"][0x3F]['X'], ctrkeys["defaultKeyslots"][0x3F]['Y'])

print("Generating Console Unique keys")
def decryptKeys(f, size=64):
    f.read(36)
    aesiv = f.read(16)
    o=f.tell()
    conunique = f.read(64)
    f.seek(o+size)
    return io.BytesIO(AES.new(ctrkeys["defaultKeyslots"][0x3F]['N'].to_bytes(16, 'big'), AES.MODE_CBC, aesiv).encrypt(conunique))
with open("data/boot9.bin", "rb") as boot9:
    if ctrkeys["isDev3DS"]:
        boot9.seek(0xDC60)
    else:
        boot9.seek(0xD860)
    boot9.read(36)
    f = decryptKeys(boot9)
    keys(f, 0x04, 'X')
    keys(f, 0x08, 'X')
    keys(f, 0x0C, 'X')
    o=f.tell()
    boot9keys[0x10]['X'] = int.from_bytes(f.read(16), 'big')
    f.seek(o)

    f = decryptKeys(boot9, 16)
    keys_inc(f, 0x14, 'X')

    f = decryptKeys(boot9)
    keys(f, 0x18, 'X')
    keys(f, 0x1C, 'X')
    keys(f, 0x20, 'X')
    o=f.tell()
    boot9keys[0x24]['X'] = int.from_bytes(f.read(16), 'big')
    f.seek(o)

    f = decryptKeys(boot9, 16)
    keys_inc(f, 0x28, 'X')

if ctrkeys["isN3DS"]:
    ctrkeys["defaultKeyslots"][0x05]['Y'] = 0x4D804F4E9990194613A204AC584460BE
    ctrkeys["defaultKeyslots"][0x05]['N'] = scramble(ctrkeys["defaultKeyslots"][0x05]['X'], ctrkeys["defaultKeyslots"][0x05]['Y'])


print(yaml.dump(ctrkeys, default_flow_style=False))
