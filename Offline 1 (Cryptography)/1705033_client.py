from cgitb import reset
from unittest import result
from BitVector import *
from audioop import add
import stat
import numpy as np
import math
import os

# Import socket module
import socket			

# AES encryption
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

roundConstantList = [
        [0x01, 0x00, 0x00, 0x00],
        [0x02, 0x00, 0x00, 0x00],
        [0x04, 0x00, 0x00, 0x00],
        [0x08, 0x00, 0x00, 0x00],
        [0x10, 0x00, 0x00, 0x00],
        [0x20, 0x00, 0x00, 0x00],
        [0x40, 0x00, 0x00, 0x00],
        [0x80, 0x00, 0x00, 0x00],
        [0x1b, 0x00, 0x00, 0x00],
        [0x36, 0x00, 0x00, 0x00]
]

AES_modulus = BitVector(bitstring='100011011')

# method to convert text to Hex
def charToHex(text):
  hexString = ""
  for i in range(len(text)):
    hexString += format(ord(text[i]), "x")
    hexString += " "
  return hexString

#convert int to hex
def intToHex(x):
    return hex(x)[2:]

# convert hex to ascii
def hexToAscii(stateMatrix):
    asciiString = ""
    for i in range(len(stateMatrix)):
        ch = chr(int(stateMatrix[i], 16))
        asciiString += ch
    return asciiString

# calculate g[w3]
def g(w3, roundConstant):
    #circular byte left shift
    temp0 = w3[0]
    temp1 = w3[1]
    temp2 = w3[2]
    temp3 = w3[3]

    newList = w3.copy()

    newList[0] = temp1
    newList[1] = temp2
    newList[2] = temp3
    newList[3] = temp0

    #Byte Substitution
    for i in range(len(newList)):
        b = BitVector(hexstring=newList[i])
        int_val = b.intValue()
        s = Sbox[int_val]
        s = BitVector(intVal=s, size=8)
        newList[i] = s.get_bitvector_in_hex()

    #Adding Round Constant
    result = [0x00, 0x00, 0x00, 0x00]
    for i in range(len(result)):
        result[i] = int(newList[i], 16) ^ roundConstant[i]
        result[i] = intToHex(result[i])
        
    return result

# method to generate all the round keys
def generateRoundKeys(w0, w1, w2, w3, allRoundKeys):
    list0 = []
    list1 = []
    list2 = []
    list3 = []
    for i in range(10):
        w0 = doXor(w0, g(w3, roundConstantList[i]))
        w1 = doXor(w0, w1)
        w2 = doXor(w1, w2)
        w3 = doXor(w2, w3)
        #roundKey Matrix generation
        list0.clear()
        list1.clear()
        list2.clear()
        list3.clear()

        list0.append(w0[0])
        list0.append(w1[0])
        list0.append(w2[0])
        list0.append(w3[0])
        allRoundKeys.append(list0.copy())

        list1.append(w0[1])
        list1.append(w1[1])
        list1.append(w2[1])
        list1.append(w3[1])
        allRoundKeys.append(list1.copy())

        list2.append(w0[2])
        list2.append(w1[2])
        list2.append(w2[2])
        list2.append(w3[2])
        allRoundKeys.append(list2.copy())

        list3.append(w0[3])
        list3.append(w1[3])
        list3.append(w2[3])
        list3.append(w3[3])
        allRoundKeys.append(list3.copy())
    return allRoundKeys

def addRoundKey(stateMatrix, roundKey):
    for i in range(len(stateMatrix)):
        for j in range(len(stateMatrix)):
            stateMatrix[i][j] = int(stateMatrix[i][j], 16) ^ int(roundKey[i][j], 16)
            stateMatrix[i][j] = intToHex(stateMatrix[i][j])
    return stateMatrix

def byteSubstitution(stateMatrix):
    for i in range(len(stateMatrix)):
        for j in range(len(stateMatrix)):
            b = BitVector(hexstring=stateMatrix[i][j])
            int_val = b.intValue()
            s = Sbox[int_val]
            s = BitVector(intVal=s, size=8)
            stateMatrix[i][j] = s.get_bitvector_in_hex()
    return stateMatrix

def shiftRow(stateMatrix):
    rows, cols = (4, 4)
    rowShiftedMatrix = [[0 for i in range(cols)] for j in range(rows)]
    # keep 1st row intact
    rowShiftedMatrix[0][0], rowShiftedMatrix[0][1], rowShiftedMatrix[0][2], rowShiftedMatrix[0][3] = stateMatrix[0][0], stateMatrix[0][1], stateMatrix[0][2], stateMatrix[0][3]
    # shift each element of 2nd row 1 step to the left 
    rowShiftedMatrix[1][0], rowShiftedMatrix[1][1], rowShiftedMatrix[1][2], rowShiftedMatrix[1][3] = stateMatrix[1][1], stateMatrix[1][2], stateMatrix[1][3], stateMatrix[1][0] 
    # shift each element of 3rd row 2 steps to the left
    rowShiftedMatrix[2][0], rowShiftedMatrix[2][1], rowShiftedMatrix[2][2], rowShiftedMatrix[2][3] = stateMatrix[2][2], stateMatrix[2][3], stateMatrix[2][0], stateMatrix[2][1]
    # shift each element of 4th row 3 steps to the left
    rowShiftedMatrix[3][0], rowShiftedMatrix[3][1], rowShiftedMatrix[3][2], rowShiftedMatrix[3][3] = stateMatrix[3][3], stateMatrix[3][0], stateMatrix[3][1], stateMatrix[3][2]
    return rowShiftedMatrix

def mixColumn(stateMatrix):
    rows, cols = (4, 4)
    mixedColumnMatrix = [[0 for i in range(cols)] for j in range(rows)]
    # 1st Row
    for j in range(len(stateMatrix)):
        temp = 0
        bv1 = BitVector(hexstring="02")
        bv2 = BitVector(hexstring=stateMatrix[0][j])
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        temp ^= int(bv3)
        bv1 = BitVector(hexstring="03")
        bv2 = BitVector(hexstring=stateMatrix[1][j])
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        temp ^= int(bv3)
        temp ^= int(stateMatrix[2][j], 16)
        temp ^= int(stateMatrix[3][j], 16)
        mixedColumnMatrix[0][j] = intToHex(temp)
    # 2nd Row
    for j in range(len(stateMatrix)):
        temp = 0
        temp ^= int(stateMatrix[0][j], 16)
        bv1 = BitVector(hexstring="02")
        bv2 = BitVector(hexstring=stateMatrix[1][j])
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        temp ^= int(bv3)
        bv1 = BitVector(hexstring="03")
        bv2 = BitVector(hexstring=stateMatrix[2][j])
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        temp ^= int(bv3)
        temp ^= int(stateMatrix[3][j], 16)
        mixedColumnMatrix[1][j] = intToHex(temp)
    # 3rd Row
    for j in range(len(stateMatrix)):
        temp = 0
        temp ^= int(stateMatrix[0][j], 16)
        temp ^= int(stateMatrix[1][j], 16)
        bv1 = BitVector(hexstring="02")
        bv2 = BitVector(hexstring=stateMatrix[2][j])
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        temp ^= int(bv3)
        bv1 = BitVector(hexstring="03")
        bv2 = BitVector(hexstring=stateMatrix[3][j])
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        temp ^= int(bv3)
        mixedColumnMatrix[2][j] = intToHex(temp)
    # 4th Row
    for j in range(len(stateMatrix)):
        temp = 0
        bv1 = BitVector(hexstring="03")
        bv2 = BitVector(hexstring=stateMatrix[0][j])
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        temp ^= int(bv3)
        temp ^= int(stateMatrix[1][j], 16)
        temp ^= int(stateMatrix[2][j], 16)
        bv1 = BitVector(hexstring="02")
        bv2 = BitVector(hexstring=stateMatrix[3][j])
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        temp ^= int(bv3)
        mixedColumnMatrix[3][j] = intToHex(temp)
    return mixedColumnMatrix

def doXor(w0, w1):
    result = [0x00, 0x00, 0x00, 0x00]
    for i in range(len(w0)):
        result[i] = int(w0[i], 16) ^ int(w1[i], 16)
        result[i] = intToHex(result[i])
    return result

# plainText = input("Plain Text : ")
# print("In HEX:")
# plainTextToHex = charToHex(plainText)
# print(plainTextToHex)
# key = input("Key: ")
# print("In HEX:")
# keyToHex = charToHex(key)
# print(keyToHex)

# # The first Roundkey
# keyToHexArray = keyToHex.split()
# w0 = keyToHexArray[0:4]
# w1 = keyToHexArray[4:8]
# w2 = keyToHexArray[8:12]
# w3 = keyToHexArray[12:16]

# #roundKey Matrix generation
# list0 = []
# list1 = []
# list2 = []
# list3 = []
# roundKey = []
# allRoundKeys = []

# list0.append(w0[0])
# list0.append(w1[0])
# list0.append(w2[0])
# list0.append(w3[0])
# roundKey.append(list0)
# allRoundKeys.append(list0.copy())

# list1.append(w0[1])
# list1.append(w1[1])
# list1.append(w2[1])
# list1.append(w3[1])
# roundKey.append(list1)
# allRoundKeys.append(list1.copy())

# list2.append(w0[2])
# list2.append(w1[2])
# list2.append(w2[2])
# list2.append(w3[2])
# roundKey.append(list2)
# allRoundKeys.append(list2.copy())

# list3.append(w0[3])
# list3.append(w1[3])
# list3.append(w2[3])
# list3.append(w3[3])
# roundKey.append(list3)
# allRoundKeys.append(list3.copy())

# #stateMatrix generation
# plainTextToHexArray = plainTextToHex.split()
# a0 = plainTextToHexArray[0:4]
# a1 = plainTextToHexArray[4:8]
# a2 = plainTextToHexArray[8:12]
# a3 = plainTextToHexArray[12:16]

# list4 = []
# list5 = []
# list6 = []
# list7 = []
# stateMatrix = []

# list4.append(a0[0])
# list4.append(a1[0])
# list4.append(a2[0])
# list4.append(a3[0])
# stateMatrix.append(list4)

# list5.append(a0[1])
# list5.append(a1[1])
# list5.append(a2[1])
# list5.append(a3[1])
# stateMatrix.append(list5)

# list6.append(a0[2])
# list6.append(a1[2])
# list6.append(a2[2])
# list6.append(a3[2])
# stateMatrix.append(list6)

# list7.append(a0[3])
# list7.append(a1[3])
# list7.append(a2[3])
# list7.append(a3[3])
# stateMatrix.append(list7)

# stateMatrix = addRoundKey(stateMatrix, roundKey)


# for i in range(10):
#     stateMatrix = byteSubstitution(stateMatrix)
#     stateMatrix = shiftRow(stateMatrix)
#     if i != 9:
#         stateMatrix = mixColumn(stateMatrix)
#     w0 = doXor(w0, g(w3, roundConstantList[i]))
#     w1 = doXor(w0, w1)
#     w2 = doXor(w1, w2)
#     w3 = doXor(w2, w3)
#     #roundKey Matrix generation
#     list0.clear()
#     list1.clear()
#     list2.clear()
#     list3.clear()
#     roundKey.clear()

#     list0.append(w0[0])
#     list0.append(w1[0])
#     list0.append(w2[0])
#     list0.append(w3[0])
#     roundKey.append(list0)
#     allRoundKeys.append(list0.copy())


#     list1.append(w0[1])
#     list1.append(w1[1])
#     list1.append(w2[1])
#     list1.append(w3[1])
#     roundKey.append(list1)
#     allRoundKeys.append(list1.copy())

#     list2.append(w0[2])
#     list2.append(w1[2])
#     list2.append(w2[2])
#     list2.append(w3[2])
#     roundKey.append(list2)
#     allRoundKeys.append(list2.copy())

#     list3.append(w0[3])
#     list3.append(w1[3])
#     list3.append(w2[3])
#     list3.append(w3[3])
#     roundKey.append(list3)
#     allRoundKeys.append(list3.copy())

#     stateMatrix = addRoundKey(stateMatrix, roundKey)
 
# cypherTextInHex = []   
# print("\nCipher Text:")
# print("In HEX:")
# for i in range(len(stateMatrix)):
#     for j in range(len(stateMatrix)):
#         print(stateMatrix[j][i], end = " ")
#         cypherTextInHex.append(stateMatrix[j][i])

plainText = input("Plain Text : ")
print("In HEX:")
plainTextToHex = charToHex(plainText)
        
print(plainTextToHex)
key = input("Key: ")
print("In HEX:")
keyToHex = charToHex(key)
print(keyToHex)

keyToHexArray = keyToHex.split()
if(len(keyToHexArray) > 16):
    keyToHexArray = keyToHexArray[0:16]
# Padding
if(len(keyToHexArray) < 16):
    paddingLength = 16 - len(keyToHexArray)
    for i in range(paddingLength):
        keyToHexArray.append('00')

# The first Roundkey
w0 = keyToHexArray[0:4]
w1 = keyToHexArray[4:8]
w2 = keyToHexArray[8:12]
w3 = keyToHexArray[12:16]

#roundKey Matrix generation
list0 = []
list1 = []
list2 = []
list3 = []
roundKey = []
allRoundKeys = []

list0.append(w0[0])
list0.append(w1[0])
list0.append(w2[0])
list0.append(w3[0])
allRoundKeys.append(list0.copy())


list1.append(w0[1])
list1.append(w1[1])
list1.append(w2[1])
list1.append(w3[1])
allRoundKeys.append(list1.copy())

list2.append(w0[2])
list2.append(w1[2])
list2.append(w2[2])
list2.append(w3[2])
allRoundKeys.append(list2.copy())

list3.append(w0[3])
list3.append(w1[3])
list3.append(w2[3])
list3.append(w3[3])
allRoundKeys.append(list3.copy())

allRoundKeys = generateRoundKeys(w0, w1, w2, w3, allRoundKeys)

plainTextToHexArray = plainTextToHex.split()

# Padding
if(len(plainTextToHexArray) % 16 != 0):
    paddingLength = 16 - (len(plainTextToHexArray) % 16)
    for i in range(paddingLength):
        plainTextToHexArray.append('00')

startIndex = 0
encryptedMatrixList = []

while startIndex < len(plainTextToHexArray):
    a0 = plainTextToHexArray[startIndex : startIndex + 4]
    a1 = plainTextToHexArray[startIndex + 4 : startIndex + 8]
    a2 = plainTextToHexArray[startIndex + 8 : startIndex + 12]
    a3 = plainTextToHexArray[startIndex + 12 : startIndex + 16]

    #stateMatrix generation
    list4 = []
    list5 = []
    list6 = []
    list7 = []
    stateMatrix = []

    list4.append(a0[0])
    list4.append(a1[0])
    list4.append(a2[0])
    list4.append(a3[0])
    stateMatrix.append(list4)


    list5.append(a0[1])
    list5.append(a1[1])
    list5.append(a2[1])
    list5.append(a3[1])
    stateMatrix.append(list5)

    list6.append(a0[2])
    list6.append(a1[2])
    list6.append(a2[2])
    list6.append(a3[2])
    stateMatrix.append(list6)

    list7.append(a0[3])
    list7.append(a1[3])
    list7.append(a2[3])
    list7.append(a3[3])
    stateMatrix.append(list7)
    
    roundKey.clear()
    roundKey.append(allRoundKeys[0])
    roundKey.append(allRoundKeys[1])
    roundKey.append(allRoundKeys[2])
    roundKey.append(allRoundKeys[3])
    stateMatrix = addRoundKey(stateMatrix, roundKey)

    allRoundKeyStartIndex = 4
    for i in range(10):
        stateMatrix = byteSubstitution(stateMatrix)
        stateMatrix = shiftRow(stateMatrix)
        if i != 9:
            stateMatrix = mixColumn(stateMatrix)
        roundKey.clear()
        roundKey.append(allRoundKeys[allRoundKeyStartIndex].copy())
        allRoundKeyStartIndex += 1
        roundKey.append(allRoundKeys[allRoundKeyStartIndex].copy())
        allRoundKeyStartIndex += 1
        roundKey.append(allRoundKeys[allRoundKeyStartIndex].copy())
        allRoundKeyStartIndex += 1
        roundKey.append(allRoundKeys[allRoundKeyStartIndex].copy())
        allRoundKeyStartIndex += 1
        stateMatrix = addRoundKey(stateMatrix, roundKey)

    for i in range(len(stateMatrix)):
        for j in range(len(stateMatrix)):
            encryptedMatrixList.append(stateMatrix[j][i])

    list4.clear()
    list5.clear()
    list6.clear()
    list7.clear()
    stateMatrix.clear()
    startIndex += 16
    

# RSA Encryption  
def getRelativePrime(n) :
    p = 3
    while True :
        if math.gcd(p, n) == 1:
            return p
        p = p + 2
        
# Key-Pair Generation
# Select Two Prime Numbers p & q where p != q
# generate p
while True:
    bv = BitVector(intVal = 0)
    bv = bv.gen_random_bits(128)  
    check = bv.test_for_primality()
    if check > 0.9:
        p = int(bv)
        break
    
# generate q
while True:
    bv = BitVector(intVal = 0)
    bv = bv.gen_random_bits(8)  
    check = bv.test_for_primality()
    if check > 0.9 and int(bv) != p:
        q = int(bv)
        break
    
# Calculate n = p * q
n = p * q

# Calculate Phi(n)
phi_n = (p - 1) * (q - 1)

# Select e such that e is relatively co-prime to phi_n
# Euler's Totient Algorithm
e = getRelativePrime(phi_n)
# print(e)

# Multiplicative inverse of e mod phi_n
bv_modulus = BitVector(intVal = phi_n)
bv = BitVector(intVal = e) 
d = int(bv.multiplicative_inverse( bv_modulus ))

publicKey = []
publicKey.append(e)
publicKey.append(n)

print("\n\nPublic Key = {", e, ",", n, "}")
print("Private Key = {", d, ",", n, "}")

try: 
    os.mkdir("Don't Open This") 
except OSError as error: 
    print("\n\nDirectory Already Exists\n")

print("\n\nStoring Private Key in a Secret Folder...")    
f = open("Don't Open This/private_key.txt", mode = "w")
f.write(str(d))
f.write("\n")
f.write(str(n))
f.close()
print("Stored Successfully!")


# We want to encrypt the input key
key = list(key)
if len(key) > 16:
    key = key[0:16]
if(len(key) < 16):
    paddingLength = 16 - len(key)
    for i in range(paddingLength):
        key.append('\0')
print("\nKey to be encrypted using rsa:")
print(key)

# Do Encryption character by character
cypherText = []
for i in range(len(key)):
    asciiValue = ord(key[i])
    cypherText.append(pow(asciiValue, e, n))
print("\nAfter Encryption:")
print(cypherText)

# Create a socket object
s = socket.socket()		

# Define the port on which you want to connect
port = 12345			

# connect to the server on local computer
s.connect(('127.0.0.1', port))

# Convert To String
cypherTextInHex = str(encryptedMatrixList)
# Encode String
cypherTextInHex = cypherTextInHex.encode()
# Send Encoded String version of the List
print("\nSending AES Encrypted Cypher Text...")
s.send(cypherTextInHex)
print (s.recv(1024).decode())

cypherText = str(cypherText)
# Encode String
cypherText = cypherText.encode()
print("\nSending RSA Encrypted Key...")
s.send(cypherText)
print (s.recv(1024).decode())

publicKey = str(publicKey)
# Encode String
publicKey = publicKey.encode()
print("\nSending RSA Public Key...")
s.send(publicKey)
print (s.recv(1024).decode())

# receive data from the server and decoding to get the string.
print (s.recv(1024).decode())

#open text file in read mode
decypheredFile = open("Don't Open This/decyphered_text.txt", "r")
 
#read whole file to a string
data = decypheredFile.read()

if plainText == data:
    print("\n\nMatched Successfully!!")
else:
    print("\n\nDidn't Match the Decyphered Text")

print(s.recv(1024).decode())
# close the connection
s.close()	
	
