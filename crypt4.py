import asn1tools
import hashlib
import random
import math
from sympy import mod_inverse


def jacob(a, n):
    g = 1
    s = 1
    if (a == 1):
        return g
    while (a != 0):
        a1 = a
        k = 0
        while (a1 % 2 == 0):
            k += 1
            a1 //= 2
        if (k % 2 == 0):
            s = 1
        elif (n % 8 == 1 or n % 8 == 7):
            s = 1
        elif (n % 8 == 3 or n % 8 == 5):
            s = -1
        if (a1 == 1):
            return (g * s)
        if (n % 4 == 3 and a1 % 4 == 3):
            s = -s
        a = n % a1
        n = a1
        g = g * s
    if (a == 0):
        return 0


def solovey(n, test_count):
    prime = 1
    k = 0
    for i in range(test_count):
        a = int(random.uniform(2, n - 2))
        r = pow(a, (n - 1) // 2, n)
        if r != 1 and r != n - 1:
            return False
        j = jacob(a, n)
        if r != (j % n):
            return False
        if prime != 0:
            k += 1
    return True


def next_simple_after(num):
    next_num = num + 1
    while not solovey(next_num, 10):
        next_num += 1
    return next_num


def GenPrime(bitlen):
    tmp = random.getrandbits(bitlen)
    while tmp.bit_length() < bitlen:
        tmp = random.getrandbits(bitlen)
    tmp = next_simple_after(tmp)
    while tmp.bit_length() < bitlen:
        tmp = next_simple_after(tmp)
        print(tmp.bit_length())
    print(tmp)
    return tmp


def GenSign(file):
    signeble_file = open(file, "rb")
    sing_file = open(file + "_sign.dat", 'wb')
    readFile = signeble_file.read()
    sha1Hash = hashlib.sha1(readFile)
    hash_int = int(sha1Hash.hexdigest(), 16)
    k = random.randrange(r)
    while math.gcd(k, r) != 1:
        k = random.randrange(r)
    w = pow(g, k, p)
    s = ((hash_int - x * w) * mod_inverse(k, r)) % (r)

    sign = el_gamal_sign_file.encode('ElGamalSignFile', dict(keyset={
        'key': dict
            (
            algid=b'\x80\x06\x02\x00', test='testSign', keydata=
        {
            'b': b
        }
            , param={'prime': p, 'r': r, 'generator': g},
            ciphertext=dict
                (
                w=w, s=s
            )
        )
    }, last={}))
    sing_file.write(sign)
    sing_file.close()
    print("sign generated")
    return file + "_sign.dat"


def AuthSign(file, sign):
    sign_file = open(sign, 'rb')
    sign_data = sign_file.read()
    sign_str = el_gamal_sign_file.decode('ElGamalSignFile', sign_data)
    w = sign_str['keyset']['key']['ciphertext']['w']
    s = sign_str['keyset']['key']['ciphertext']['s']
    g = sign_str['keyset']['key']['param']['generator']
    b = sign_str['keyset']['key']['keydata']['b']
    if (w >= p):
        print("w>=p, error")
        return False

    source_file = open(file, "rb")
    readFile = source_file.read()
    sha1Hash = hashlib.sha1(readFile)
    message_hash = int(sha1Hash.hexdigest(), 16)
    first = pow(g, message_hash, p)
    # print("first", first)
    second = pow(pow(b, w, p) * pow(w, s, p), 1, p)
    # print("second", second)
    if first == second:
        print("sign true")
        return True
    else:
        print("sign false")
        return False


el_gamal_sign_file = asn1tools.compile_files('schemes/el_gamal_sign.asn')

p = GenPrime(512)  # prime
g = random.randrange(p - 1)  # generator
x = random.randrange(p - 1)  # secret
b = pow(g, x, p)  # open key
r = p - 1
print("keys generated")
sign = GenSign("otvety.txt")
AuthSign("otvety - Copy.txt", "otvety.txt_sign.dat")
AuthSign("otvety.txt", "otvety.txt_sign.dat")
