# first of all import the socket library
import socket
from BitVector import *

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

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
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

def addRoundKey(stateMatrix, roundKey):
    for i in range(len(stateMatrix)):
        for j in range(len(stateMatrix)):
            stateMatrix[i][j] = int(stateMatrix[i][j], 16) ^ int(roundKey[i][j], 16)
            stateMatrix[i][j] = intToHex(stateMatrix[i][j])
    return stateMatrix

def inverseByteSubstitution(stateMatrix):
    for i in range(len(stateMatrix)):
        for j in range(len(stateMatrix)):
            b = BitVector(hexstring=stateMatrix[i][j])
            int_val = b.intValue()
            s = InvSbox[int_val]
            s = BitVector(intVal=s, size=8)
            stateMatrix[i][j] = s.get_bitvector_in_hex()
    return stateMatrix

def inverseShiftRow(stateMatrix):
    rows, cols = (4, 4)
    rowShiftedMatrix = [[0 for i in range(cols)] for j in range(rows)]
    # keep 1st row intact
    rowShiftedMatrix[0][0], rowShiftedMatrix[0][1], rowShiftedMatrix[0][2], rowShiftedMatrix[0][3] = stateMatrix[0][0], stateMatrix[0][1], stateMatrix[0][2], stateMatrix[0][3]
    # shift each element of 2nd row 1 step to the right 
    rowShiftedMatrix[1][1], rowShiftedMatrix[1][2], rowShiftedMatrix[1][3], rowShiftedMatrix[1][0] = stateMatrix[1][0], stateMatrix[1][1], stateMatrix[1][2], stateMatrix[1][3] 
    # shift each element of 3rd row 2 steps to the right
    rowShiftedMatrix[2][2], rowShiftedMatrix[2][3], rowShiftedMatrix[2][0], rowShiftedMatrix[2][1] = stateMatrix[2][0], stateMatrix[2][1], stateMatrix[2][2], stateMatrix[2][3]
    # shift each element of 4th row 3 steps to the right
    rowShiftedMatrix[3][3], rowShiftedMatrix[3][0], rowShiftedMatrix[3][1], rowShiftedMatrix[3][2] = stateMatrix[3][0], stateMatrix[3][1], stateMatrix[3][2], stateMatrix[3][3]
    return rowShiftedMatrix

def inverseMixColumn(stateMatrix):
    rows, cols = (4, 4)
    mixedColumnMatrix = [[0 for i in range(cols)] for j in range(rows)]
    for i in range(len(stateMatrix)):
        for j in range(len(stateMatrix)):
            temp = 0
            for k in range(len(stateMatrix)):
                bv1 = InvMixer[i][k]
                bv2 = BitVector(hexstring=stateMatrix[k][j])
                bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
                temp ^= int(bv3)
            mixedColumnMatrix[i][j] = intToHex(temp)
    return mixedColumnMatrix

def doXor(w0, w1):
    result = [0x00, 0x00, 0x00, 0x00]
    for i in range(len(w0)):
        result[i] = int(w0[i], 16) ^ int(w1[i], 16)
        result[i] = intToHex(result[i])
    return result

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

def rsaDecrypt(encryptedKey, d, n):
    #Do Decryption character by character
    decypheredString = ""
    for i in range(len(encryptedKey)):
        decypheredCharacter = pow(encryptedKey[i], d, n)
        decypheredString += chr(decypheredCharacter)	
    return decypheredString

# next create a socket object
s = socket.socket()		
print ("Socket successfully created")

# reserve a port on your computer in our
# case it is 12345 but it can be anything
port = 12345			

# Next bind to the port
# we have not typed any ip in the ip field
# instead we have inputted an empty string
# this makes the server listen to requests
# coming from other computers on the network
s.bind(('', port))		
print ("socket binded to %s" %(port))

# put the socket into listening mode
s.listen(5)	
print ("socket is listening")		

# a forever loop until we interrupt it or
# an error occurs
while True:

    # Establish connection with client.
    c, addr = s.accept()	
    print ('Got connection from', addr )
    
    data = c.recv(4096)
    # Decode received data into UTF-8
    data = data.decode('utf-8')
    # Convert decoded data into list
    encryptedText = eval(data)
    
    print("\nReceived AES Encrypted Text:")
    print(encryptedText)
    
    c.send("\nServer: Received AES Encrypted Cypher Text Successfully".encode())
    
    data = c.recv(4096)
    # Decode received data into UTF-8
    data = data.decode('utf-8')
    # Convert decoded data into list
    encryptedKey = eval(data)
    
    print("\nReceived RSA Encrypted Key:")
    print(encryptedKey)
    
    c.send("\nServer: Received RSA Encrypted Key Successfully".encode())
    
    data = c.recv(4096)
    # Decode received data into UTF-8
    data = data.decode('utf-8')
    # Convert decoded data into list
    publicKey = eval(data)
    
    print("\nReceived RSA Public Key:")
    print(publicKey)
    
    c.send("\nServer: Received RSA Public Key Successfully".encode())
    
    file1 = open("Don't Open This/private_key.txt", 'r')
    Lines = file1.readlines()
    
    privateKey = []
    # Strips the newline character
    for line in Lines:
        privateKey.append(int(line))
    
    d = privateKey[0]
    n = privateKey[1]
    
    print("\nDecrypting key using RSA...")
    decryptedKey = rsaDecrypt(encryptedKey, d, n)
    print("The Decrypted Key is:", decryptedKey)
    
    keyToHex = charToHex(decryptedKey)
    keyToHexArray = keyToHex.split()
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
    
    startIndex = 0
    loopCount = len(encryptedText) / 16
    decryptedMatrixList = []
    
    while startIndex < loopCount * 16:
        a0 = encryptedText[startIndex : startIndex + 4]
        a1 = encryptedText[startIndex + 4 : startIndex + 8]
        a2 = encryptedText[startIndex + 8 : startIndex + 12]
        a3 = encryptedText[startIndex + 12 : startIndex + 16]

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
        roundKey.append(allRoundKeys[40].copy())
        roundKey.append(allRoundKeys[41].copy())
        roundKey.append(allRoundKeys[42].copy())
        roundKey.append(allRoundKeys[43].copy())

        stateMatrix = addRoundKey(stateMatrix, roundKey)
        allRoundKeyStartIndex = 36

        for i in range(10):
            stateMatrix = inverseShiftRow(stateMatrix)
            stateMatrix = inverseByteSubstitution(stateMatrix)
            roundKey.clear()
            roundKey.append(allRoundKeys[allRoundKeyStartIndex].copy())
            allRoundKeyStartIndex += 1
            roundKey.append(allRoundKeys[allRoundKeyStartIndex].copy())
            allRoundKeyStartIndex += 1
            roundKey.append(allRoundKeys[allRoundKeyStartIndex].copy())
            allRoundKeyStartIndex += 1
            roundKey.append(allRoundKeys[allRoundKeyStartIndex].copy())
            allRoundKeyStartIndex -= 7
            stateMatrix = addRoundKey(stateMatrix, roundKey)
            if i != 9:
                stateMatrix = inverseMixColumn(stateMatrix)
        for i in range(len(stateMatrix)):
            for j in range(len(stateMatrix)):
                decryptedMatrixList.append(stateMatrix[j][i])
        list4.clear()
        list5.clear()
        list6.clear()
        list7.clear()
        stateMatrix.clear()
        startIndex += 16
    print("Deciphered Text:")
    print("In HEX:")
    print(decryptedMatrixList)
    print("\nIn ASCII:")
    print(hexToAscii(decryptedMatrixList))
    
    print("\n\nWriting Decyphered Text to the directory...")
    f = open("Don't Open This/decyphered_text.txt", mode = "w")
    f.write(hexToAscii(decryptedMatrixList).rstrip('\x00'))
    f.close()
    print("Stored Successfully!")
    c.send("\n\nServer: Please Kindly Match the Decrypted Text with the Original Text".encode())
    # send a thank you message to the client. encoding to send byte type.
    c.send('\n\nServer: Thank you for connecting'.encode())

    # Close the connection with the client
    c.close()

    # Breaking once connection closed
    break
