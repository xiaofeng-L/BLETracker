import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import donna25519 as curve25519
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


def key_gen(cloud_pub_key, ble_mac_addr, rand):
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

    ECDH_priv_key_ble = curve25519.PrivateKey(bytes(priv_key_ble))
    ECDH_pub_key_clo = curve25519.PublicKey(bytes(cloud_pub_key))
    MasterSecretKey = ECDH_priv_key_ble.do_exchange(ECDH_pub_key_clo)

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


if __name__ == '__main__':

    encryptionKey_base64 = "Fjlj47HUSoc6xbkc0xhXbj-j2IxNIdXdI6PsmXluAOs=".encode()
    uuid_base64 = "NuG05A+4BHi0hlT+hDVIMA==".encode()
    cloud_pub_key_base64 = "Bwnsud1mI1XzowMD8RC0T7lUWn0qc53oAUtOrPJUrTk=".encode()
    rand_base64 = "NTYwOGIxMDMzODg0MzA3ODc0NDExODA2MDJiYTdmYWEyYzczNTQ2NzQ3NzhjNzBkOTFiZGQ1NDRkNDgwZDFlNg==".encode()
    adv_id_base64 = "AAAAAAAHQfo=".encode()
    iv_base64 = "sZrpLq5wRnq95PEBJ7QusQ==".encode()

    ble_mac_addr = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    encryptionKey = base64.urlsafe_b64decode(encryptionKey_base64)
    uuid = base64.urlsafe_b64decode(uuid_base64)
    cloud_pub_key = base64.urlsafe_b64decode(cloud_pub_key_base64)
    rand = base64.urlsafe_b64decode(rand_base64)
    adv_id = base64.urlsafe_b64decode(adv_id_base64)
    iv = base64.urlsafe_b64decode(iv_base64)

    # print("encryptionKey", encryptionKey_base64, encryptionKey.hex(), encryptionKey)
    # print("uuid", uuid_base64, uuid.hex(), uuid)
    # print("cloud_pub_key", cloud_pub_key_base64, cloud_pub_key.hex(), cloud_pub_key)
    # print("rand", rand_base64, rand.hex(), rand)
    # print("adv_id", adv_id_base64, adv_id.hex(), adv_id)
    # print("iv", iv_base64, iv.hex(), iv)

    privacy, signing, bleAuthentication, nonOwner, ENC_KEY, MasterSecretKey, priv_key_ble = key_gen(cloud_pub_key, ble_mac_addr, rand)



    # mes_updated, key_updated = rand2_init(bytes_init(0x20))
    # print(mes_updated.hex(), key_updated.hex())
    # rand_2, mes_updated, key_updated = sub_35444(mes_updated, key_updated)
    # privId = privId_gen(rand_2, adv_id, iv, privacy)
    # print(privId[:8], privId.hex())
    # rand_2, mes_updated, key_updated = sub_35444(mes_updated, key_updated)
    # privId = privId_gen(rand_2, adv_id, iv, privacy)
    # print(privId[:8], privId.hex())

    # calculate all privId
    # privId_all = []
    # for i in range(1001):
    #     rand_2 = bytes([i >> 8, i & 0xff])
    #     tmp = privId_gen(rand_2, adv_id, iv, privacy)
    #     print(i, tmp.hex())
    #     privId_all.append(tmp)
    # # print(privId_all)

    # 2 96e866f843d73d033bf0a4f6686a2dc0
    print(2)
    fake_privId_adv = bytes([0x12,0xed,0xee,0x00,0x59,0x50,0xac,0x56,0x80,0x61,0x0e,0x4a,0xa3,0x00,0x00,0x00])
    fake_signing = sign_gen(fake_privId_adv, iv, signing)[:4]
    print("fake_privId_adv", fake_privId_adv)
    print("fake_signing", fake_signing)
    fake_adv = fake_privId_adv + fake_signing
    print("fake_adv", fake_adv.hex())
    print(base64.urlsafe_b64encode(fake_adv))

    print(1)
    print(timeStamp())
