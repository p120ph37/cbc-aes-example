package crypt_example;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import crypt_example.CBCAESBouncyCastle;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class CBCAESBouncyCastleTest 
    extends TestCase
{
    public CBCAESBouncyCastleTest( String testName )
    {
        super( testName );
    }

    public static Test suite()
    {
        return new TestSuite( CBCAESBouncyCastleTest.class );
    }

    /**
     * Test
     * @throws InvalidCipherTextException 
     * @throws DataLengthException 
     * @throws NoSuchAlgorithmException 
     * @throws UnsupportedEncodingException 
     */
    public void testCBCAESBouncyCastle() throws DataLengthException, InvalidCipherTextException, NoSuchAlgorithmException, UnsupportedEncodingException
    {
        new CBCAESBouncyCastle();
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey sk = kg.generateKey();

        CBCAESBouncyCastle cabc = new CBCAESBouncyCastle();
        cabc.setKey(sk.getEncoded());

        String input = "This is a secret message!";
        System.out.println("Input[" + input.length() + "]: " + input);

        byte[] plain = input.getBytes("UTF-8");
        System.out.println("Plaintext[" + plain.length + "]: " + Hex.encodeHexString(plain));

        byte[] encr = cabc.encrypt(plain);
        System.out.println("Encrypted[" + encr.length + "]: " + Hex.encodeHexString(encr));

        byte[] decr = cabc.decrypt(encr);
        System.out.println("Decrypted[" + decr.length + "]: " + Hex.encodeHexString(decr));

        String output = new String(decr, "UTF-8");
        System.out.println("Output[" + output.length() + "]: " + output);

        assertEquals(input.length(), output.length());
        assertEquals(input, output);
    }
}
