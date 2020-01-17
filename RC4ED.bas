/'
Usage (Encryption): RC4ED plaintext.file ciphertext.file password
Usage (Decryption): RC4ED ciphertext.file plaintext.file password
Compiled by free basic. free basic website: www.freebasic.net

Algorithm:
    Dim As UByte S(255), T(255), index, key
    Dim As UInteger i, j, l

    For i = 0 To 255
        S(i) = i

        T(i) = Key[i mod KeyLength]
    Next i

    j = 0

    For i = 0 To 255
        j = (j + S(i) + T(i)) mod 256

        swap(S(i), S(j))
    Next i

    i = 0

    j = 0

    For l = 0 To FileSize - 1 Do
        i = (i + 1) mod 256

        j = (j + S(i)) mod 256

        swap(S(i), S(j))

        index = (S(i) + S(j)) mod 256

        key = S(index)

        Ciphertext(l) = Plaintext(l) Xor key
        Plaintext(l) = Ciphertext(l) Xor key
    Next k
'/

#include "file.bi"

' define S box
Sub KSA(aubS() As UByte, ByVal sKey As String, ByVal uiKeyLength As UInteger)
    Dim As UInteger i, j

    For i = 0 To 255 : aubS(i) = i : Next i

    j = 0

    For i = 0 To 255
        j = (j + aubS(i) + CUByte(sKey[i mod uiKeyLength])) mod 256

' swap data
        Swap aubS(i), aubS(j)
    Next i
End Sub

' pseudo random-number generation algorithm for producing key stream
Sub PRGA(aubS() As UByte, aubKeyStream() As UByte, ByVal uiFileSize As UInteger)
    Dim As UInteger i, j, k

    i = 0

    j = 0

    For k = 0 To uiFileSize - 1
        i = (i + 1) mod 256

        j = (j + aubS(i)) mod 256

' swap data
        Swap aubS(i), aubS(j)

        aubKeyStream(k) = aubS((aubS(i) + aubS(j)) mod 256)
    Next k
End Sub

Dim As UByte aubS(255), aubKeyStream(), aubPlaintextOrCiphertext()

Dim As UInteger uiFileSize

' get the plaintext or ciphertext file size
uiFileSize = FileLen(Command(1))

ReDim aubPlaintextOrCiphertext(uiFileSize - 1)

' open the plaintext or ciphertext file
Open Command(1) For Binary Access Read As #1

' read data from the plaintext or ciphertext file
Get #1, , aubPlaintextOrCiphertext()

Close #1

' initialize S box
KSA(aubS(), Command(3), Len(Command(3)))

ReDim aubKeyStream(uiFileSize - 1)

' produce key stream
PRGA(aubS(), aubKeyStream(), uiFileSize)

' encrypt or decrypt by XOR
For i As UInteger = 0 To uiFileSize - 1
    aubPlaintextOrCiphertext(i) Xor= aubKeyStream(i)
Next i

Erase aubKeyStream

' open the ciphertext or plaintext file
Open Command(2) For Binary Access Write As #2

' write datat to the ciphertext or plaintext file
Put #2, , aubPlaintextOrCiphertext()

Close #2

Erase aubPlaintextOrCiphertext