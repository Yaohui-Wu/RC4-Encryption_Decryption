<?php
/*
Usage (Encryption): php RC4ED.php plaintext.file ciphertext.file password
Usage (Decryption): php RC4ED.php ciphertext.file plaintext.file password

Algorithm:
    $S=[];

    $T=[];

    for($i=0;$i<256;++$i)
    {
        $S[$i]=$i;

        $T[$i]=ord($Key[$i%KeyLength]);
    }

    $j=0;

    for($i=0;$i<256;++$i)
    {
        $j=($j+$S[$i]+$T[$i])%256;

        list($S[$i],$S[$j])=[$S[$j],$S[$i]];
    }

    $i=0;

    $j=0;

    for($l=0;$l<FileSize;++$l)
    {
        $i=($i+1)%256;

        $j=($j+$S[$i])%256;

        list($S[$i],$S[$j])=[$S[$j],$S[$i]];

        $index=($S[$i]+$S[$j])%256;

        $key=$S[$index];

        Ciphertext[$l]=Plaintext[$l]^$key;
        Plaintext[$l]=Ciphertext[$l]^$key;
    }
*/

# define S box
function KSA(&$aS,$sKey)
{
    for($i=0;$i<256;++$i)
    {
        $aS[$i]=$i;
    }

    $j=0;

    for($i=0;$i<256;++$i)
    {
        $j=($j + $aS[$i] + ord($sKey[$i%strlen($sKey)]))%256;

# swap data
        list($aS[$i],$aS[$j])=[$aS[$j],$aS[$i]];
    }
}

# pseudo random-number generation algorithm for producing key stream
function PRGA(&$aS,&$aKeyStream,$iFileSize)
{
    $i=0;

    $j=0;

    for($k=0;$k<$iFileSize;++$k)
    {
        $i=($i+1)%256;

        $j=($j+$aS[$i])%256;

# swap data
        list($aS[$i],$aS[$j])=[$aS[$j],$aS[$i]];

        $aKeyStream[$k]=$aS[($aS[$i]+$aS[$j])%256];
    }
}

# get the plaintext or ciphertext file size
$iFileSize=filesize($argv[1]);

# open the plaintext or ciphertext file
$dPlaintextOrCiphertext=fopen($argv[1],'rb') or die("Can't open the plaintext file.");

# read data from the plaintext or ciphertext file
$sPlaintextOrCiphertext=fread($dPlaintextOrCiphertext,$iFileSize) or die("Can't read the plaintext file.");

fclose($dPlaintextOrCiphertext);

$aS=[];

# initialize S box
KSA($aS,$argv[3]);

$aKeyStream=[];

# produce key stream
PRGA($aS,$aKeyStream,$iFileSize);

# encrypt or decrypt by XOR
for($i=0;$i<$iFileSize;++$i)
{
    $sPlaintextOrCiphertext[$i]=chr(ord($sPlaintextOrCiphertext[$i])^$aKeyStream[$i]);
}

# open the ciphertext or plaintext file
$dPlaintextOrCiphertext=fopen($argv[2],'wb') or die("Can't open the ciphertext file.");

# write datat to the ciphertext or plaintext file
fwrite($dPlaintextOrCiphertext,$sPlaintextOrCiphertext) or die("Can't write the ciphertext file.");

fclose($dPlaintextOrCiphertext);