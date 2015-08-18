package cbc_aes_example;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;

import cbc_aes_example.CBCAESBouncyCastle;
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
    public void testCBCAESBouncyCastle() throws UnsupportedEncodingException, DataLengthException, InvalidCipherTextException 
    {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        random.nextBytes(key);
 
        CBCAESBouncyCastle cabc = new CBCAESBouncyCastle();
        cabc.setKey(key);

        String input = "This is a secret message!";
        System.out.println("Input[" + input.length() + "]: " + input);

        byte[] plain = input.getBytes("UTF-8");
        System.out.println("Plaintext[" + plain.length + "]: " + new String(Hex.encode(plain)));

        byte[] encr = cabc.encrypt(plain);
        System.out.println("Encrypted[" + encr.length + "]: " + new String(Hex.encode(encr)));

        byte[] decr = cabc.decrypt(encr);
        System.out.println("Decrypted[" + decr.length + "]: " + new String(Hex.encode(decr)));

        String output = new String(decr, "UTF-8");
        System.out.println("Output[" + output.length() + "]: " + output);

        assertEquals(input.length(), output.length());
        assertEquals(input, output);
    }
}
