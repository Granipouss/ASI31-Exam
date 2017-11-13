import sys
import numpy as np
from Crypto.Protocol import KDF
from Crypto.Cipher import AES

# = CONSTANTES ===
BLOCK_SIZE = 16
KEY_SIZE = 256

# = BLOCK BASIC OPERATIONS ===
def toInt (s):
    return int(s.encode('hex'), 16)

def int2hex_block (n):
    return (hex(n)[2:-1]).zfill(2 * BLOCK_SIZE).decode('hex')

def xor_block (A, B):
    return int2hex_block(toInt(A) ^ toInt(B))

def incr_block (A, n = 1):
    return int2hex_block(toInt(A) + n)

# = BLOCKLIST OPERATIONS ===
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
    l = int(blocks[-1][-1], 16)
    if l == 0:
        return blocks[:-1]
    else:
        unpadded = blocks[:]
        unpadded[-1] = blocks[-1][0:BLOCK_SIZE-l]
        return unpadded

# = KEY GENERATION ===
def gen_key (pwd, IV):
    kSize = KEY_SIZE / 8
    totalSize = BLOCK_SIZE + 2 * kSize
    key = KDF.PBKDF2(pwd, salt=IV, dkLen=totalSize, count=10000)
    K1 = key[0*kSize:1*kSize]
    K2 = key[1*kSize:2*kSize]
    R = key[2*kSize:totalSize]
    return (K1, K2, R)

# = BLOCK CRYPTO OPERATIONS ===
def encrypt_block (key, msg):
    return AES.new(key).encrypt(msg)

def decrypt_block (key, msg):
    return AES.new(key).decrypt(msg)

# = IACBC CRYPTO OPERATIONS ===
def xor_all (P):
    Q = P[0]
    for i in range(1, len(P)):
        Q = xor_block(Q, P[i])
    return Q

def gen_S (K1, K2, R, l):
    return [encrypt_block(K2, incr_block(R, n+1)) for n in range(l)]

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

# = MAIN OPERATIONS ===
def encrypt (pwd, IV, msg):
    K1, K2, R = gen_key(pwd, IV)
    return encrypt_iacbc(K1, K2, R, msg)

def decrypt (pwd, IV, c):
    K1, K2, R = gen_key(pwd, IV)
    return decrypt_iacbc(K1, K2, R, c)
