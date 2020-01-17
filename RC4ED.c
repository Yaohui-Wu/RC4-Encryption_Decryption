/*
Usage (Encryption): RC4ED plaintext.file ciphertext.file password
Usage (Decryption): RC4ED ciphertext.file plaintext.file password

Algorithm:
    unsigned char S[256], T[256];

    swap(unsigned char *pucSi, unsigned char *pucSj)
    {
        unsigned char ucTemp = *pucSi;

        *pucSi = *pucSj;

        *pucSj = ucTemp;
    }

    for(unsigned long long i = 0; i < 256; ++i)
    {
        S[i] = i;

        T[i] = Key[i % KeyLength];
    }

    for(unsigned long long j = 0, i = 0; i < 256; ++i)
    {
        j = (j + S[i] + T[i]) % 256;

        swap(S[i], S[j]);
    }

    for(unsigned long long i = 0, j = 0, l = 0; l < FileSize; ++l)
    {
        i = (i + 1) % 256;

        j = (j + S[i]) % 256;

        swap(S[i], S[j]);

        unsigned char index = (S[i] + S[j]) % 256;

        unsigned char key = S[index];

        Ciphertext[l] = Plaintext[l] ^ key;
        Plaintext[l] = Ciphertext[l] ^ key;
    }
*/

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

// swap data
void Swap(unsigned char *pucSi, unsigned char *pucSj)
{
    unsigned char ucTemp = *pucSi;

    *pucSi = *pucSj;

    *pucSj = ucTemp;
}

// define S box
void KSA(unsigned char *pucS, unsigned char *pucKey, unsigned long long ulKeyLength)
{
    for(unsigned long long i = 0; i < 256; ++i)
    {
        pucS[i] = i;
    }

    for(unsigned long long j = 0, i = 0; i < 256; ++i)
    {
        j = (j + pucS[i] + pucKey[i % ulKeyLength]) % 256;

        Swap(pucS + i, pucS + j);
    }
}

// pseudo random-number generation algorithm for producing key stream
void PRGA(unsigned char *pucS, unsigned char *pucKeyStream, unsigned long long ulFileSize)
{
    for(unsigned long long i = 0, j = 0, k = 0; k < ulFileSize; ++k)
    {
        i = (i + 1) % 256;

        j = (j + pucS[i]) % 256;

        Swap(pucS + i, pucS + j);

        pucKeyStream[k] = pucS[(pucS[i] + pucS[j]) % 256];
    }
}

int main(int argc, char *argv[])
{
    struct stat statFileSize;

    stat(argv[1], &statFileSize);

// get the plaintext or ciphertext file size
    unsigned long long ulFileSize = statFileSize.st_size;

// allocate storage space
    unsigned char *pucPlaintextOrCiphertext = (unsigned char*)malloc(ulFileSize);

// open the plaintext or ciphertext file
    int iPlaintextOrCiphertextFD = open(argv[1], O_BINARY | O_RDONLY, S_IREAD | S_IWRITE);

// read data from the plaintext or ciphertext file
    read(iPlaintextOrCiphertextFD, pucPlaintextOrCiphertext, ulFileSize);
	
    close(iPlaintextOrCiphertextFD);

    unsigned char aucS[256];

// any password length
    unsigned long long ulKeyLength = -1;

// get the password length
    while(argv[3][++ulKeyLength]);

// initialize S box
    KSA(aucS, (unsigned char*)argv[3], ulKeyLength);

    unsigned char *pucKeyStream = (unsigned char*)malloc(ulFileSize);

// produce key stream
    PRGA(aucS, pucKeyStream, ulFileSize);

// encrypt or decrypt by XOR
    for(unsigned long i = 0; i < ulFileSize; ++i)
    {
        pucPlaintextOrCiphertext[i] ^= pucKeyStream[i];
    }

    free(pucKeyStream);

// open the ciphertext or plaintext file
    iPlaintextOrCiphertextFD = open(argv[2], O_BINARY | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);

// write datat to the ciphertext or plaintext file
    write(iPlaintextOrCiphertextFD, pucPlaintextOrCiphertext, ulFileSize);

    close(iPlaintextOrCiphertextFD);

    free(pucPlaintextOrCiphertext);

    return 0;
}