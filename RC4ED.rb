=begin
Usage (Encryption): ruby RC4ED plaintext.file ciphertext.file password
Usage (Decryption): ruby RC4ED ciphertext.file plaintext.file password

Algorithm:
    S=[];

    T=[];

    (0...256).each do |i|
        S[i]=i;

        T[i] = Key[i%KeyLength];
    end

    j=0;

    (0...256).each do |i|
        j=(j+S[i]+T[i])%256;

        S[i],S[j]=S[j],S[i];
    end

    i=0;

    j=0;

    for l in 0...FileSize
        i=(i+1)%256;

        j=(j+S[i])%256;

        S[i],S[j]=S[j],S[i];

        index=(S[i]+S[j])%256;

        key=S[index];

        Ciphertext[l]=Plaintext[l]^key;
        Plaintext[l]=Ciphertext[l]^key;
    end
=end

# define S box
def KSA(aS,sKey)
    (0...256).each do |i|
        aS[i]=i;
    end

    j=0;

    (0...256).each do |i|
        j=(j+aS[i]+sKey[i%sKey.length].ord)%256;

        aS[i],aS[j]=aS[j],aS[i];
    end
end

# pseudo random-number generation algorithm for producing key stream
def PRGA(aS,aKeyStream,iPlaintextOrCiphertextLength)
    i=0;

    j=0;

    for k in 0...iPlaintextOrCiphertextLength
        i=(i+1)%256;

        j=(j+aS[i])%256;

        aS[i],aS[j]=aS[j],aS[i];

        aKeyStream[k]=aS[(aS[i]+aS[j])%256];
    end
end

# read data from the plaintext or ciphertext file
sPlaintextOrCiphertext=File.binread(ARGV[0]);  

aS=[];

# initialize S box
KSA(aS,ARGV[2]);

aKeyStream=[];

# produce key stream
PRGA(aS,aKeyStream,sPlaintextOrCiphertext.length);

aPlaintextOrCiphertext=sPlaintextOrCiphertext.bytes;

# encrypt or decrypt by XOR
(0...sPlaintextOrCiphertext.length).each do |i|
    sPlaintextOrCiphertext[i]=(aPlaintextOrCiphertext[i]^aKeyStream[i]).chr;
end

# write data to the plaintext or ciphertext file
File.binwrite(ARGV[1],sPlaintextOrCiphertext);