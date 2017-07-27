from os.path import expanduser
import yaml
ctrkeys={
    "keyscrambler": {
            "ctr":0x1FF9E9AAC5FE0408024591DC5D52768A,
            "twl":int.from_bytes("任天堂株式会社".encode("UTF-16"), "big")
        },
    "contents": [
            "keyscrambler"
        ]
    }

try:
    with open(expanduser("~/ctrkeys.yaml")) as f:
        ctrkeys=yaml.load(f.read())
except:
    pass

def savekeys():
    def hexint_presenter(dumper, data):
        return dumper.represent_int(hex(data))
    yaml.add_representer(int, hexint_presenter)
    with open(expanduser("~/ctrkeys.yaml"), "w") as f:
        f.write(yaml.dump(ctrkeys, default_flow_style=False))
