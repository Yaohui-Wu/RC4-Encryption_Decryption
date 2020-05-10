'''
Usage (Encryption): python RC4ED.py plaintext.file ciphertext.file password
Usage (Decryption): python RC4ED.py ciphertext.file plaintext.file password

Algorithm:
    S=[]

    T=[]

    for i in range(256):
        S[i]=i

        T[i]=Key[i%KeyLength]

    j=0

    for i in range(256):
        j=(j+S[i]+T[i])%256

        S[i],S[j]=S[j],S[i]

    i=0

    j=0

    for l in range(FileSize):
        i=(i+1)%256

        j=(j+S[i])%256

        S[i],S[j]=S[j],S[i]

        index=(S[i]+S[j])%256

        key=S[index]

        Ciphertext[l]=Plaintext[l]^key
        Plaintext[l]=Ciphertext[l]^key
'''

#-*-coding:utf-8-*-

import io, sys, os.path

# define S box
def KSA(lS, cKey): 
    j = 0

    for i in range(256):
        j = (j + lS[i] + cKey[i % len(cKey)]) % 256

# swap data
        lS[i], lS[j] = lS[j], lS[i]

# pseudo random-number generation algorithm for producing key stream
def PRGA(lS, aKeyStream, iFileSize):
    i = j = 0

    for k in range(iFileSize):
        i = (i + 1) % 256

        j = (j + lS[i]) % 256

# swap data
        lS[i], lS[j] = lS[j], lS[i]

        aKeyStream[k] = lS[(lS[i] + lS[j]) % 256]

if __name__=='__main__':
# open the plaintext or ciphertext file
    with open(sys.argv[1], 'br', 0) as hPlaintextOrCiphertext:

# read data from the plaintext or ciphertext file
        aPlaintextOrCiphertext = bytearray(hPlaintextOrCiphertext.readall())

# get the size of plaintext or ciphertext file
        iFileSize = hPlaintextOrCiphertext.tell()

    lS = list(range(256))

# initialize S box
    KSA(lS, sys.argv[3].encode('ascii'))

    aKeyStream = bytearray(iFileSize)

# produce key stream
    PRGA(lS, aKeyStream, iFileSize)

# encrypt or decrypt by XOR
    for i in range(iFileSize): aPlaintextOrCiphertext[i] ^= aKeyStream[i]

# open the ciphertext or plaintext file
    with open(sys.argv[2], 'bw', 0) as hCiphertextOrPlaintext:

# write datat to the ciphertext or plaintext file
        hCiphertextOrPlaintext.write(aPlaintextOrCiphertext)
