{
Usage (Encryption): RC4ED plaintext.file ciphertext.file password
Usage (Decryption): RC4ED ciphertext.file plaintext.file password
Compiled by free pascal. free pascal website: www.freepascal.org

Algorithm:
    S, T:Array[Byte] Of Byte;
    index, key:Byte;
    i, j, l:Int64;

    swap(Var bSi:Byte; Var bSj:Byte)
    Var
        bTemp:Byte;

    Begin
        bTemp := bSi;

        bSi := bSj;

        bSj := bTemp;
    End

    For i := 0 To 255 Do
    Begin
        S[i] := i;

        T[i] := Key[i mod KeyLength];
    End

    j := 0;

    For i := 0 To 255 Do
    Begin
        j := (j + S[i] + T[i]) mod 256;

        swap(S[i], S[j]);
    End

    i := 0;

    j := 0;

    For l := 0 To FileSize - 1 Do
    Begin
        i := (i + 1) mod 256;

        j := (j + S[i]) mod 256;

        swap(S[i], S[j]);

        index := (S[i] + S[j]) mod 256;

        key := S[index];

        Ciphertext[l] := Plaintext[l] Xor key;
        Plaintext[l] := Ciphertext[l] Xor key;
    End
}

Program RC4EncryptionDecryption;
Type
    ArrayByte = Array[Byte] Of Byte;

Var
    abS:ArrayByte;

    llFileSize, i:Int64;

    dPlaintextOrCiphertext:File;

    pbPlaintextOrCiphertext, pbKeyStream:PByte;

// swap data
Procedure Swap(Var bSi:Byte; Var bSj:Byte);
Var
    bTemp:Byte;

Begin
    bTemp := bSi;

    bSi := bSj;

    bSj := bTemp;
End;

// define S box
Procedure KSA(Var abS:ArrayByte; sKey:String; llKeyLength:Int64);
Var
    i, j:Int64;

Begin
    For i := 0 To 255 Do abS[i] := i;

    j := 0;

    For i := 0 To 255 Do
    Begin
        j := (j + abS[i] + Ord(sKey[i mod llKeyLength + 1])) mod 256;

        Swap(abS[i], abS[j]);
    End;
End;

// pseudo random-number generation algorithm for producing key stream
Procedure PRGA(Var abS:ArrayByte; Var bKeyStream:PByte; llFileSize:Int64);
Var
    i, j, k:Int64;

Begin
    i := 0;

    j := 0;

    For k := 0 To llFileSize - 1 Do
    Begin
        i := (i + 1) mod 256;

        j := (j + abS[i]) mod 256;

        Swap(abS[i], abS[j]);

        bKeyStream[k] := abS[(abS[i] + abS[j]) mod 256];
    End;
End;

Begin
// open the plaintext or ciphertext file
    Assign(dPlaintextOrCiphertext, ParamStr(1));

    Reset(dPlaintextOrCiphertext, 1);

// get the plaintext or ciphertext file size
    llFileSize := FileSize(dPlaintextOrCiphertext);

// allocate storage space
    pbPlaintextOrCiphertext := GetMem(llFileSize);

// read data from the plaintext or ciphertext file
    BlockRead(dPlaintextOrCiphertext, pbPlaintextOrCiphertext^, llFileSize);

    Close(dPlaintextOrCiphertext);

// initialize S box
    KSA(abS, ParamStr(3), Length(ParamStr(3)));

    pbKeyStream := GetMem(llFileSize);

// produce key stream
    PRGA(abS, pbKeyStream, llFileSize);

// encrypt or decrypt by XOR
    For i := 0 To llFileSize - 1 Do pbPlaintextOrCiphertext[i] := pbPlaintextOrCiphertext[i] Xor pbKeyStream[i];

    Freemem(pbKeyStream);

// open the ciphertext or plaintext file
    Assign(dPlaintextOrCiphertext, Paramstr(2));

    Rewrite(dPlaintextOrCiphertext, 1);

// write datat to the ciphertext or plaintext file
    BlockWrite(dPlaintextOrCiphertext, pbPlaintextOrCiphertext^, llFileSize);

    Close(dPlaintextOrCiphertext);

    Freemem(pbPlaintextOrCiphertext);
End.