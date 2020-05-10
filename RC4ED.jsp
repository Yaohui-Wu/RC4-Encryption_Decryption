<%--
Algorithm:
    byte[] S = new byte[256];

    byte[] T = new byte[256];

    swap(byte[] S, int i, int j)
    {
        i &= 255; j &= 255;

        byte bTemp = S[i];

        S[i] = S[j];

        S[j] = bTemp;
    }

    for(int i = 0; i < 256; ++i)
    {
        S[i] = (byte)i;

        T[i] = Key[i % KeyLength];
    }

    for(int j = 0, i = 0; i < 256; ++i)
    {
        j = j + S[i] + T[i] & 255;

        swap(S[i], S[j]);
    }

    for(int i = 0, j = 0, l = 0; l < FileSize; ++l)
    {
        i = i + 1 & 255;

        j = j + S[i] & 255;

        swap(S[i], S[j]);

        byte index = S[i] + S[j] & 256;

        byte key = S[index];

        Ciphertext[l] = Plaintext[l] ^ key;
        Plaintext[l] = Ciphertext[l] ^ key;
    }
--%>

<%@ page import="java.io.*" %>
<%!
// swap data
void Swap(byte[] abS, int i, int j)
{
    i &= 255; j &= 255;

    byte bTemp = abS[i];

    abS[i] = abS[j];

    abS[j] = bTemp;
}

// define S box
void KSA(byte[] abS, final byte[] abKey)
{
    for(int i = 0; i < 256; ++i)
    {
        abS[i] = (byte)i;
    }

    for(int j = 0, i = 0; i < 256; ++i)
    {
        j = j + abS[i] + abKey[i % abKey.length] & 255;

        Swap(abS, i, j);
    }
}

// pseudo random-number generation algorithm for producing key stream
void PRGA(byte[] abS, byte[] abKeyStream, int iFileSize)
{
    for(int i = 0, j = 0, k = 0; k < iFileSize; ++k)
    {
        i = i + 1 & 255;

        j = j + abS[i] & 255;

        Swap(abS, i, j);

        abKeyStream[k] = abS[abS[i] + abS[j] & 255];
    }
}
%>
<%
    String sPlaintext = request.getParameter("Plaintext");

    String sCiphertext = request.getParameter("Ciphertext");

    String sPassword = request.getParameter("Password");

    if(sPlaintext != null && sCiphertext != null && sPassword != null)
    {
        File dPlaintextOrCiphertext = new File(sPlaintext);

// get the plaintext or ciphertext file size
        int iFileSize = (int)dPlaintextOrCiphertext.length();

// allocate storage space
        byte[] abPlaintextOrCiphertext = new byte[iFileSize];

        try
        {
// open the plaintext or ciphertext file
            FileInputStream fisPlaintextCiphertext = new FileInputStream(dPlaintextOrCiphertext);

// read data from the plaintext or ciphertext file
            fisPlaintextCiphertext.read(abPlaintextOrCiphertext, 0, iFileSize);

            fisPlaintextCiphertext.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

        byte[] abS = new byte[256];

// initialize S box
        KSA(abS, sPassword.getBytes());

        byte[] abKeyStream = new byte[iFileSize];

// produce key stream
        PRGA(abS, abKeyStream, iFileSize);

// encrypt or decrypt by XOR
        for(int i = 0; i < iFileSize; ++i)
        {
            abPlaintextOrCiphertext[i] ^= abKeyStream[i];
        }

        dPlaintextOrCiphertext = new File(sCiphertext);

        try
        {
// create the ciphertext or plaintext file
            dPlaintextOrCiphertext.createNewFile();

// open the ciphertext or plaintext file
            FileOutputStream fosCiphertextPlaintext = new FileOutputStream(dPlaintextOrCiphertext);

// write datat to the ciphertext or plaintext file
            fosCiphertextPlaintext.write(abPlaintextOrCiphertext, 0, iFileSize);

            fosCiphertextPlaintext.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
%>
<!doctype html>
<html><head>
    <meta charset=UTF-8>
    <title> RC4 Encryption and Decryption for JSP</title>
    <script>
        function checkForm()
        {
            document.getElementById('Plaintext').value = prompt('Enter a plaintext or ciphertext');

            document.getElementById('Ciphertext').value = prompt('Enter a ciphertext or plaintext');

            document.getElementById('Password').value = prompt('Enter a password');
        }
    </script>
</head><body>
    <form id=RC4ED target=_self mothed=get action=RC4ED.jsp onsubmit=checkForm()>
        <input type=submit value='Encryption and Decryption'>
        <input id=Plaintext type=hidden name=Plaintext>
        <input id=Ciphertext type=hidden name=Ciphertext>
        <input id=Password type=hidden name=Password>
    </form>
</body></html>