'''
Usage (Encryption): python RC4ED plaintext.file ciphertext.file password
Usage (Decryption): python RC4ED ciphertext.file plaintext.file password

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

import io,sys,os.path

# define S box
def KSA(lS,cKey): 
    j=0

    for i in range(256):
        j=(j+lS[i]+cKey[i%len(cKey)])%256

# exchange data
        lS[i],lS[j]=lS[j],lS[i]

# pseudo random-number generation algorithm for producing key stream
def PRGA(lS,bKeyStream,nPlaintextOrCiphertextLength):
    i=0

    j=0

    for k in range(nPlaintextOrCiphertextLength):
        i=(i+1)%256

        j=(j+lS[i])%256

# exchange data
        lS[i],lS[j]=lS[j],lS[i]

        bKeyStream[k]=lS[(lS[i]+lS[j])%256]

if __name__=='__main__':
# open the plaintext or ciphertext file
    dPlaintextOrCiphertext=open(sys.argv[1],'br',0)

# read data from the plaintext or ciphertext file
    bPlaintextOrCiphertext=bytearray(dPlaintextOrCiphertext.readall())

    dPlaintextOrCiphertext.close()

    lS=list(range(256))

# initialize S box
    KSA(lS,sys.argv[3].encode('ascii'))

    iFileSize=len(bPlaintextOrCiphertext)

    bKeyStream=bytearray(iFileSize)

# produce key stream
    PRGA(lS,bKeyStream,iFileSize)

# encrypt or decrypt by XOR
    for i in range(iFileSize): bPlaintextOrCiphertext[i]^=bKeyStream[i]

# open the ciphertext or plaintext file
    dPlaintextOrCiphertext=open(sys.argv[2],'bw',0)

# write datat to the ciphertext or plaintext file
    dPlaintextOrCiphertext.write(bPlaintextOrCiphertext)

    dPlaintextOrCiphertext.close()