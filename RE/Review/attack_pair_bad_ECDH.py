import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
# import donna25519 as curve25519
import time


def xor(a, b):
    c = []
    for i in range(len(a)):
        c.append(a[i] ^ b[i])
    return bytes(c)


def add_1(a):
    b = []
    for i in a:
        b.append((i+1) & 0xff)
    return bytes(b)


def bytes_init(length):
    a = []
    for i in range(length):
        a.append(0)
    return bytes(a)


def privId_gen(rand_2, adv_id, iv, key):
    # GenPrivateId, encrypting Privacy ID, with a rand number below 1000, like 0x0236
    mes = bytes(rand_2) + bytes(adv_id) + bytes(rand_2)
    cipher = AES.new(key=bytes(key), mode=AES.MODE_CBC, iv=bytes(iv))
    enc_data = cipher.encrypt(pad(mes, AES.block_size, 'pkcs7'))
    # print(enc_data)
    return enc_data


def sign_gen(mes, iv, key):
    mes = bytes(mes)[:16]
    cipher = AES.new(key=bytes(key), mode=AES.MODE_CBC, iv=bytes(iv))
    enc_data = cipher.encrypt(mes)
    # print(enc_data)
    return enc_data


def key_gen(cloud_pub_key, ble_mac_addr, rand, shared_secret):
    """
    SHA-512(BLE_GAP_ADDR(6 Bytes) + 0) 并修改第1字节和第0x1f字节
    nrf_crypto_ecdh_compute(NULL, &priv_key1, &pub_key2, shared_secret, &shared_secret_len)
    Message0 = SHA-256(MasterSecretKey+CloudRandomNum)
    ENC_KEY_INUSE = SHA-256(Message0 + 0x1000000 + “Specific Strings”)
    :param cloud_pub_key:
    :param ble_mac_addr:
    :param rand:
    """
    # MasterSecretKey or shared_secret
    priv_key_ble_mes = bytes(ble_mac_addr) + bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    # sub_3802c
    sha512 = hashlib.new("sha512")
    sha512.update(priv_key_ble_mes)
    priv_key_ble = sha512.digest()[:32]
    priv_key_ble_0 = priv_key_ble[0] & 0xf8
    priv_key_ble_31 = (priv_key_ble[-1] & 0x3f) | 0x40
    priv_key_ble = bytes([priv_key_ble_0]) + bytes(priv_key_ble[1:-1]) + bytes([priv_key_ble_31])
    # sub_3805c
    sha512 = hashlib.new("sha512")
    sha512.update(priv_key_ble)
    priv_key_ble = sha512.digest()[:32]
    priv_key_ble_0 = priv_key_ble[0] & 0xf8
    priv_key_ble_31 = (priv_key_ble[-1] & 0x7f) | 0x40
    priv_key_ble = bytes([priv_key_ble_0]) + bytes(priv_key_ble[1:-1]) + bytes([priv_key_ble_31])
    #
    # ECDH_priv_key_ble = curve25519.PrivateKey(bytes(priv_key_ble))
    # ECDH_pub_key_clo = curve25519.PublicKey(bytes(cloud_pub_key))
    # MasterSecretKey = ECDH_priv_key_ble.do_exchange(ECDH_pub_key_clo)
    MasterSecretKey = shared_secret

    # rand
    rand_32 = []
    for i in range(0x20):
        if rand[i*2] > 0x39:
            temp1 = rand[i*2] - 0x57
        else:
            temp1 = rand[i*2] - 0x30
        if rand[i*2+1] > 0x39:
            temp2 = rand[i*2+1] - 0x57
        else:
            temp2 = rand[i*2+1] - 0x30
        temp = ((temp1*16) | temp2) % 0x100
        rand_32.append(temp)
    rand_32 = bytes(rand_32)
    # print("rand_32", rand_32.hex(), rand_32)

    # ENC KEY
    sha256 = hashlib.new("sha256")
    sha256.update(bytes(MasterSecretKey)+bytes(rand_32))
    ENC_KEY = sha256.digest()
    ENC_KEY = shared_secret

    # ENC_KEY_INUSE
    sha256 = hashlib.new("sha256")
    sha256.update(bytes(ENC_KEY[:16]) + bytes([0, 0, 0, 1]) + "privacy".encode())
    privacy = sha256.digest()[:16]

    sha256 = hashlib.new("sha256")
    sha256.update(bytes(ENC_KEY[:16]) + bytes([0, 0, 0, 1]) + "signing".encode())
    signing = sha256.digest()[:16]

    sha256 = hashlib.new("sha256")
    sha256.update(bytes(ENC_KEY[:16]) + bytes([0, 0, 0, 1]) + "bleAuthentication".encode())
    bleAuthentication = sha256.digest()[:16]

    sha256 = hashlib.new("sha256")
    sha256.update(bytes(ENC_KEY[:16]) + bytes([0, 0, 0, 1]) + "nonOwner".encode())
    nonOwner = sha256.hexdigest()[:16]

    return privacy, signing, bleAuthentication, nonOwner, ENC_KEY, MasterSecretKey, priv_key_ble


def clz(num):
    # 返回有几个0
    i = 32
    if num == 0:
        return 32
    else:
        while num != 0:
            num = num >> 1
            i = i - 1
        return i


def timeStamp():
    # 6 DDD0 01F4
    # 懒着翻译了
    # sub_3bbb4(time+0xa102dcbc, adc, 0x384, 0)
    # Aging Count
    tmp = int(time.time()) + 0xa102dcbc - 0x100000000
    r0 = tmp
    r1 = tmp + 1
    # r0 = 0xDDD001F4
    # r1 = 6
    r2 = 0x384
    r3 = 0

    r5 = clz(r3)
    r6 = r3
    if r6 == 0:
        r5 = clz(r2)
        r4 = (r2 << r5) % 0x100000000
        r5 = 0x20 - r5
    else:
        r4 = (r3 << r5) % 0x100000000
        r6 = r2
        r5 = 0x20 - r5
        r7 = r2 >> r5
        r4 = r4 | r7
        r5 = r5 + 0x20
    r12 = r6 | ((r4 << 0x10) % 0x100000000)
    r4 = r4 >> 0x10
    if r12 != 0:
        r4 = r4 + 1
    r11 = r4
    r9 = 0
    r8 = r9

    r12 = r1 - r3
    while r0 >= r2:
        if r1 == 0:
            r7 = clz(r0)
            r6 = (r0 << r7) % 0x100000000
            r7 = 0x20 - r7
        else:
            r7 = clz(r1)
            r6 = (r1 << r7) % 0x100000000
            r7 = 0x20 - r7
            r12 = r0 >> r7
            r6 = r6 | r12
            r7 = r7 + 0x20
        r12 = r6 // r11  # udiv
        r7 = r7 - r5
        r7 = r7 - 0x10
        r4 = r7 & 0x1f
        r6 = 0x20 - r4
        r4 = (r12 << r4) % 0x100000000
        r6 = r12 >> r6
        if r7 < 0:
            print("error")
            r4 = r6
            r6 = 0
        if r7 > 0x20:
            r6 = r4
            r4 = 0
        r12 = r4 | r6
        if r12 == 0:
            r4 = 1
        r9 = r9 + r6 + (r8 + r4)//0x100000000
        r8 = (r8 + r4) % 0x100000000
        r = r4 * r2  # umull
        r12 = r // 0x100000000
        r7 = r % 0x100000000
        r0 = r0 - r7
        r12 = (r6 * r2 + r12) % 0x100000000
        r12 = (r4 * r3 + r12) % 0x100000000
        r1 = r1 - r12
        r12 = r1 - r3

    r3 = r1
    r2 = r0
    r1 = r9
    r0 = r8
    return hex(r0)


def hexStr2bytes(hexStr):
    l = len(hexStr) // 2
    bytes_list = []
    for i in range(l):
        hex_byte = "0x"+hexStr[2*i: 2*i+2]
        bytes_list.append(eval(hex_byte))
    return bytes(bytes_list)


if __name__ == '__main__':

    encryptionKey_base64 = "VFYognG9wyE317oIhHuiw_hhhmyrWF7F_CWh9hEYdDU=".encode()
    uuid_base64 = "NuG05A+4BHi0hlT+hDVIMA==".encode()
    cloud_pub_key_base64 = "IQ-gBZ5aHyMwlemuugBPRIS2f1as5Tf2PLfaaK5IZCw=".encode()
    rand_base64 = "YmNiNmQyZTg0NmU0ODEzYjMwNWMwZDgzMjdiMGY3MGZkODkzODNhYmRkZDFlM2EwZDA0OGMyYWM3NjkyZjk3OA==".encode()
    adv_id_base64 = "AAAAAAALdzE=".encode()
    iv_base64 = "YfzoswwXRbiAq62q/gE8aA==".encode()

    # EFB5A5A42004
    ble_mac_addr = bytes([0xEF, 0xB5, 0xA5, 0xA4, 0x20, 0x04])
    encryptionKey = base64.urlsafe_b64decode(encryptionKey_base64)
    uuid = base64.urlsafe_b64decode(uuid_base64)
    cloud_pub_key = base64.urlsafe_b64decode(cloud_pub_key_base64)
    rand = base64.urlsafe_b64decode(rand_base64)
    adv_id = base64.urlsafe_b64decode(adv_id_base64)
    iv = base64.urlsafe_b64decode(iv_base64)

    # ble_mac_addr = bytes([0xCA, 0x8E, 0x57, 0x2A, 0x25, 0x48])
    # cloud_pub_key = hexStr2bytes("210fa0059e5a1f233095e9aeba004f4484b67f56ace537f63cb7da68ae48642c")
    # rand = hexStr2bytes("62636236643265383436653438313362333035633064383332376230663730666438393338336162646464316533613064303438633261633736393266393738")

    privacy, signing, bleAuthentication, nonOwner, encryptionKey_, MasterSecretKey, priv_key_ble = key_gen(cloud_pub_key, ble_mac_addr, rand, encryptionKey)

    print("cloud_pub_key", cloud_pub_key.hex(), cloud_pub_key)
    print("ble_mac_addr", ble_mac_addr.hex(), ble_mac_addr)
    print("rand", rand.hex(), rand)

    print("encryptionKey", encryptionKey.hex(), encryptionKey)
    print("adv_id", adv_id.hex(), adv_id)
    print("iv", iv.hex(), iv)
    print("MasterSecretKey", MasterSecretKey.hex(), MasterSecretKey)
    print("priv_key_ble", priv_key_ble.hex(), priv_key_ble)

    # nonce1: d4712b43f423eb2827f4524488545d7e
    # nonce2: 0ba103d4383738d79c3d6346855c40af
    # encrypted_nonce1: f13a709bcb91a67f4910dd372ef1f780
    # encrypted_nonce2: 6c4bbb0653e5bb627de8dbd1e527c988
    iv1 = hexStr2bytes("8cfc5b995993eaf6c59f2c2eec647717")
    iv2 = hexStr2bytes("aeaff87db1f17e4657b6d90f27f01585")
    encrypted_nonce1 = hexStr2bytes("f0c1f82ab372754364bd44a71fa59766")
    encrypted_nonce2 = hexStr2bytes("55ddca406d1af76d2d7171a14aaf33d0")
    cipher1 = AES.new(key=bytes(bleAuthentication), mode=AES.MODE_CBC, iv=iv1)
    dec_data1 = cipher1.decrypt(pad(encrypted_nonce2, AES.block_size, 'pkcs7'))
    cipher2 = AES.new(key=bytes(bleAuthentication), mode=AES.MODE_CBC, iv=iv2)
    dec_data2 = cipher2.decrypt(pad(encrypted_nonce1, AES.block_size, 'pkcs7'))
    print(dec_data1, dec_data2)

    # advertise_id: 21ab8d14a7759bcb45c8ebafa28c514b
    sha256 = hashlib.new("sha256")
    sha256.update(bytes(encryptionKey[:16]) + bytes([0, 0, 0, 1]) + iv2)
    link_key = sha256.digest()[:16]

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    CONFIRM_STATUS = hexStr2bytes("477c8da9baa6be367c68373fb8e78251")
    CONFIRM_STATUS = cipher.decrypt(pad(CONFIRM_STATUS, AES.block_size, 'pkcs7'))
    print("CONFIRM_STATUS", CONFIRM_STATUS)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    SUPPORTED_CONFIRM_METHOD_LIST = hexStr2bytes("44e0606b0ff1ee119ac36cdb67451ab2")
    SUPPORTED_CONFIRM_METHOD_LIST = cipher.decrypt(pad(SUPPORTED_CONFIRM_METHOD_LIST, AES.block_size, 'pkcs7'))
    print("SUPPORTED_CONFIRM_METHOD_LIST", SUPPORTED_CONFIRM_METHOD_LIST)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    SELECTED_CONFIRM_METHOD = hexStr2bytes("b5ce6884fce1528d4cb4b2653f537392")
    SELECTED_CONFIRM_METHOD = cipher.decrypt(pad(SELECTED_CONFIRM_METHOD, AES.block_size, 'pkcs7'))
    print("SELECTED_CONFIRM_METHOD", SELECTED_CONFIRM_METHOD)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    CONFIRM_RESULT = hexStr2bytes("6a853c16a91eb7acbcc235da45c59fbf")
    CONFIRM_RESULT = cipher.decrypt(pad(CONFIRM_RESULT, AES.block_size, 'pkcs7'))
    print("CONFIRM_RESULT", CONFIRM_RESULT)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    IDENTIFIER = hexStr2bytes("edea75afb62c713057d7ba5ce3c2c9c5")
    IDENTIFIER = cipher.decrypt(pad(IDENTIFIER, AES.block_size, 'pkcs7'))
    print("IDENTIFIER", IDENTIFIER)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    MNMN = hexStr2bytes("41ffa9b512ea3e41a407c808766790cfa8470afeca20dbacc02d53efe053dce0")
    MNMN = cipher.decrypt(pad(MNMN, AES.block_size, 'pkcs7'))
    print("MNMN", MNMN)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    VID = hexStr2bytes("ac37822480118401e0c8fb653c4fae7e")
    VID = cipher.decrypt(pad(VID, AES.block_size, 'pkcs7'))
    print("VID", VID)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    CONFIGURATION_VERSION = hexStr2bytes("f67aaff088a2403a7831e30b73d9a8e4")
    CONFIGURATION_VERSION = cipher.decrypt(pad(CONFIGURATION_VERSION, AES.block_size, 'pkcs7'))
    print("CONFIGURATION_VERSION", CONFIGURATION_VERSION)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    ADVERTISE_ID = hexStr2bytes("21ab8d14a7759bcb45c8ebafa28c514b")
    ADVERTISE_ID = cipher.decrypt(pad(ADVERTISE_ID, AES.block_size, 'pkcs7'))
    print("ADVERTISE_ID", ADVERTISE_ID)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    NUMBER_OF_PRIVACY_ID = hexStr2bytes("a97a8f7bd746c429160ad69f8275ea9c")
    NUMBER_OF_PRIVACY_ID = cipher.decrypt(pad(NUMBER_OF_PRIVACY_ID, AES.block_size, 'pkcs7'))
    print("NUMBER_OF_PRIVACY_ID", NUMBER_OF_PRIVACY_ID)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    REGION = hexStr2bytes("e5d470635bd4542f868ae51b49b494fb")
    REGION = cipher.decrypt(pad(REGION, AES.block_size, 'pkcs7'))
    print("REGION", REGION)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    PRIVACY_ID_IV = hexStr2bytes("1f243e205b6a632cb5ec1d64729c70859b4d890b0375aab761aa9058b1ed39df")
    PRIVACY_ID_IV = cipher.decrypt(pad(PRIVACY_ID_IV, AES.block_size, 'pkcs7'))
    print("PRIVACY_ID_IV", PRIVACY_ID_IV)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    TIME_SYNC = hexStr2bytes("7d5a1b5ecb0fd14d2a95a7e23fc36cf8")
    TIME_SYNC = cipher.decrypt(pad(TIME_SYNC, AES.block_size, 'pkcs7'))
    print("TIME_SYNC", TIME_SYNC)

    cipher = AES.new(key=bytes(link_key), mode=AES.MODE_CBC, iv=iv2)
    SETUP_COMPLETE = hexStr2bytes("98ce566947fd564e7e47bc31312b7bd1")
    SETUP_COMPLETE = cipher.decrypt(pad(SETUP_COMPLETE, AES.block_size, 'pkcs7'))
    print("SETUP_COMPLETE", SETUP_COMPLETE)
39006cd6f828978daa8651491c7d0070fc7d3a005c006cd6f828f3e9a4


