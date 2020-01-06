=pod
Usage (Encryption): perl RC4ED plaintext.file ciphertext.file password
Usage (Decryption): perl RC4ED ciphertext.file plaintext.file password

Algorithm:
    my($i,$j,$l,@S,@T);

    for($i=0;$i<256;++$i)
    {
        $S[$i]=$i;

        $T[$i]=$Key[$i%KeyLength];
    }

    $j=0;

    for($i=0;$i<256;++$i)
    {
        $j=($j+$S[$i]+$T[$i])%256;

        ($S[$i],$S[$j])=($S[$j],$S[$i]);
    }

    $i=0;

    $j=0;

    for($l=0;$l<FileSize;++$l)
    {
        $i=($i+1)%256;

        $j=($j+$S[$i])%256;

        ($S[$i],$S[$j])=($S[$j],$S[$i]);

        $index=($S[$i]+$S[$j])%256;

        $key=$S[$index];

        Ciphertext[$l]=Plaintext[$l]^$key;
        Plaintext[$l]=Ciphertext[$l]^$key;
    }
=cut

$I=1;

# define S box
sub KSA
{
    my($i,$j,@aKey);

# get the array of password
    @aKey=split('',$ARGV[2]);

    for($i=0;$i<256;++$i)
    {
        $_[0][$i]=$i;
    }

    $j=0;

    for($i=0;$i<256;++$i)
    {
        $j=($j + $_[0][$i] + ord($aKey[$i%length($ARGV[2])]))%256;

# exchange data
        ($_[0][$i],$_[0][$j])=($_[0][$j],$_[0][$i]);
    }
}

# pseudo random-number generation algorithm for producing key stream
sub PRGA
{
    my($i,$j,$k);

    $i=0;

    $j=0;

    for($k=0;$k<$_[2];++$k)
    {
        $i=($i+1)%256;

        $j=($j+$_[0][$i])%256;

# exchange data
        ($_[0][$i],$_[0][$j])=($_[0][$j],$_[0][$i]);

        $_[1][$k]=$_[0][($_[0][$i]+$_[0][$j])%256];
    }
}

my(@aS,@aKey,@aKeyStream,@aPlaintextOrCiphertext,$bPlaintextOrCiphertext,$iFileSize);

# get the plaintext or ciphertext file size
$iFileSize=-s $ARGV[0];

# open the plaintext or ciphertext file
open(PlaintextOrCiphertext,"<$ARGV[0]") || die("Can't open the file. $!");

binmode(PlaintextOrCiphertext);

# read data from the plaintext or ciphertext file
read(PlaintextOrCiphertext,$bPlaintextOrCiphertext,$iFileSize) || die("$!");

close(PlaintextOrCiphertext);

# initialize S box
KSA(\@aS);

# produce key stream
PRGA(\@aS,\@aKeyStream,$iFileSize);

# get the array of plaintext or ciphertext
@aPlaintextOrCiphertext=split('',$bPlaintextOrCiphertext);

# encrypt or decrypt by XOR
for(my $i=0;$i<$iFileSize;++$i)
{
    $aPlaintextOrCiphertext[$i]=chr(ord($aPlaintextOrCiphertext[$i])^$aKeyStream[$i]);
}

# open the ciphertext or plaintext file
open(CiphertextOrPlaintext,">$ARGV[1]") or die("Can't open the file. $!");

binmode(CiphertextOrPlaintext);

# write datat to the ciphertext or plaintext file
print(CiphertextOrPlaintext @aPlaintextOrCiphertext) or die("$!");

close(CiphertextOrPlaintext);