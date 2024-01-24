import base64
import hashlib

if __name__ == '__main__':
    ble_mac_addr = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    data_0x200085c6 = bytes([0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF])
    data_0x200085c6_f = []
    for i in data_0x200085c6:
        if i > 9:
            data_0x200085c6_f.append(i+0x37)
        else:
            data_0x200085c6_f.append(i+0x30)
    data_0x200085c6_f = bytes(data_0x200085c6_f)
    sha256 = hashlib.new("sha256")
    sha256.update(data_0x200085c6_f)
    data_0x20007da8 = sha256.digest()
    print(data_0x200085c6_f)
    print(data_0x20007da8.hex())
    print(base64.urlsafe_b64encode(data_0x20007da8))

