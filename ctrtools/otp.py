from . import ctrkeys
from . import aes
import struct
import datetime

class OTP(object):
    def __init__(self):
        if not "otp" in ctrkeys.ctrkeys["contents"]:
            OTP.parseOTP()
        self.decrypted=ctrkeys.ctrkeys["otp"]["decrypted"]
        self.aeskeydata = ctrkeys.ctrkeys["otp"]["decrypted"][0x90:0xAC]
    @staticmethod
    def parseOTP():
        try:
            with open("data/otp.mem","rb") as f:
                otpkey = aes.AESKey(ctrkeys.ctrkeys["otp"]["key"])
                otp = otpkey.decrypt("cbc", f.read(), bytes(aes.AESKey(ctrkeys.ctrkeys["otp"]["iv"])))
            magic, devID = struct.unpack("<II", otp[:8])
            assert magic == 0xDEADB00F
            ctrkeys.ctrkeys["otp"]["decrypted"] = otp
            ctrkeys.ctrkeys["otp"]["device ID"] = devID
            ctrkeys.ctrkeys["otp"]["fallback KeyY"] = int(aes.AESKey(otp[8:0x18]))
            ctrkeys.ctrkeys["otp"]["ctcert"] = {
                    "issuer": "G3_NintendoCTR2dev" if otp[0x19] else "NintendoCTR2prod",
                    "exponent": int.from_bytes(otp[0x20:0x24], 'big') if otp[0x18] >= 5 else int.from_bytes(otp[0x20:0x24], 'little'),
                    "privk": int.from_bytes(otp[0x26:0x44], 'big'),
                    "sig": int.from_bytes(otp[0x44:0x80], "big")
                }
            ctrkeys.ctrkeys["otp"]["manufacturing date"] = datetime.datetime(otp[0x1A] + 1900, otp[0x1B], otp[0x1C], otp[0x1D], otp[0x1E], otp[0x1F])
        except ValueError:
            raise
        except:
            raise ValueError("Couldn't read OTP")
        ctrkeys.ctrkeys["contents"].append("otp")
        ctrkeys.savekeys()
