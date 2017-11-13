import sys
import numpy as np
from Crypto.Protocol import KDF
from Crypto.Cipher import AES

# = CONSTANTES ===
BLOCK_SIZE = 16
KEY_SIZE = 32

def int2hex (n):
    return '{:0>32}'.format(hex(n)[2:-1]).decode('hex')

def xor_block (A, B):
    a = int(A.encode('hex'), 16)
    b = int(B.encode('hex'), 16)
    return int2hex(a ^ b)

def incr_block (A, n = 1):
    a = int(A.encode('hex'), 16)
    return int2hex(a + n)

def blockify (msg):
    return [msg[i:i + BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]

def pad (blocks):
    padded = blocks[:]
    if len(blocks[-1]) == BLOCK_SIZE:
        padded.append(BLOCK_SIZE * '0')
    else:
        l = BLOCK_SIZE - len(blocks[-1])
        padded[-1] = blocks[-1] + l * hex(l)[2:]
    return padded

def unpad (blocks):
    l = int(blocks[-1][-1].encode('hex'), 16)
    if l == 0:
        return blocks[:-1]
    else:
        unpadded = blocks[:]
        unpadded[-1] = blocks[-1][0:16-l]
        return unpadded

def gen_key (pwd, IV):
    key = KDF.PBKDF2(pwd, salt=IV, dkLen=80, count=10000)
    K1 = key[0:32]
    K2 = key[32:64]
    R = key[64:80]
    return (K1, K2, R)

def encrypt_block (key, msg):
    return AES.new(key).encrypt(msg)

def decrypt_block (key, msg):
    return AES.new(key).decrypt(msg)

def gen_S (K1, K2, R, l):
    return [encrypt_block(K2, incr_block(R, n+1)) for n in range(l)]

def xor_all (P):
    Q = P[0]
    for i in range(1, len(P)):
        Q = xor_block(Q, P[i])
    return Q

def encrypt_iacbc (K1, K2, R, msg):
    P = pad(blockify(msg))
    l = len(P)
    S = gen_S (K1, K2, R, l)

    C = [encrypt_block(K1, R)]
    for i in range(l):
        C.append(encrypt_block(K1, xor_block(C[i], P[i])))
    C.append(encrypt_block(K1, xor_block(C[l-1], xor_all(P))))

    for i in range(1, l):
        C[i] = xor_block(S[i], C[i])
    C[l] = xor_block(S[0], C[l])

    return ''.join(C)

def decrypt_iacbc (K1, K2, R, c):
    C = blockify(c)
    l = len(C) - 2
    S = gen_S (K1, K2, R, l)

    for i in range(1, l):
        C[i] = xor_block(S[i], C[i])
    C[l] = xor_block(S[0], C[l])

    P = [decrypt_block(K1, C[i]) for i in range(l+1)]

    if R != P[0]:
        return False

    for i in range(l):
        P[i+1] = xor_block(P[i+1], C[i])

    B = unpad(P[1:])
    return ''.join(B)

def encrypt (pwd, IV, msg):
    K1, K2, R = gen_key(pwd, IV)
    return encrypt_iacbc(K1, K2, R, msg)

def decrypt (pwd, IV, c):
    K1, K2, R = gen_key(pwd, IV)
    return decrypt_iacbc(K1, K2, R, c)
