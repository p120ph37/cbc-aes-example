package cbc_aes_example;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import cbc_aes_example.CTRAESBouncyCastle;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class CTRAESBouncyCastleTest 
    extends TestCase
{
    public CTRAESBouncyCastleTest( String testName )
    {
        super( testName );
    }

    public static Test suite()
    {
        return new TestSuite( CTRAESBouncyCastleTest.class );
    }

    /**
     * Test
     * @throws InvalidCipherTextException 
     * @throws DataLengthException 
     * @throws NoSuchAlgorithmException 
     * @throws UnsupportedEncodingException 
     */
    public void testCTRAESBouncyCastle() throws UnsupportedEncodingException, DataLengthException, InvalidCipherTextException 
    {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        random.nextBytes(key);
 
        CTRAESBouncyCastle cabc = new CTRAESBouncyCastle();
        cabc.setKey(key);

        // All-at-once mode...

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

        // Random-access mode, using previously-generated IV so the encrypted text can be compared...
        byte[] iv = Arrays.copyOfRange(encr, 0, cabc.blockSize);
        System.out.println("IV[" + iv.length + "]: " + new String(Hex.encode(iv)));
        // To generate one, this is the way:
        // byte[] iv = new byte[cabc.blockSize];
        // random.nextBytes(iv);

        byte[] plain1 = Arrays.copyOfRange(plain, 0, 5);
        System.out.println("Plaintext Chunk 1 [" + plain1.length + "]: " + new String(Hex.encode(plain1)));
        byte[] plain2 = Arrays.copyOfRange(plain, 5, 10);
        System.out.println("Plaintext Chunk 2 [" + plain2.length + "]: " + new String(Hex.encode(plain2)));
        byte[] plain3 = Arrays.copyOfRange(plain, 10, 15);
        System.out.println("Plaintext Chunk 3 [" + plain3.length + "]: " + new String(Hex.encode(plain3)));

        byte[] encr1 = cabc.encrypt(plain1, iv, 0);
        System.out.println("Encrypted Chunk 1 [" + encr1.length + "]: " + new String(Hex.encode(encr1)));
        byte[] encr2 = cabc.encrypt(plain2, iv, 5);
        System.out.println("Encrypted Chunk 2 [" + encr2.length + "]: " + new String(Hex.encode(encr2)));
        byte[] encr3 = cabc.encrypt(plain3, iv, 10);
        System.out.println("Encrypted Chunk 3 [" + encr3.length + "]: " + new String(Hex.encode(encr3)));

        byte[] ivAndEncr = new byte[iv.length + encr1.length + encr2.length + encr3.length];
        int o = 0;
        System.arraycopy(iv, 0, ivAndEncr, 0, iv.length);
        o += iv.length;
        System.arraycopy(encr1, 0, ivAndEncr, o, encr1.length);
        o += encr1.length;
        System.arraycopy(encr2, 0, ivAndEncr, o, encr2.length);
        o += encr2.length;
        System.arraycopy(encr3, 0, ivAndEncr, o, encr3.length);
        System.out.println("IV and Encrypted [" + ivAndEncr.length + "]: " + new String(Hex.encode(ivAndEncr)));

        assertEquals(new String(Hex.encode(Arrays.copyOfRange(encr, 0, cabc.blockSize + 15))), new String(Hex.encode(ivAndEncr)));

        int streamOffset = 10;
        byte[] encrMid = new byte[10];
        System.arraycopy(encr, cabc.blockSize + streamOffset, encrMid, 0, 10);
        System.out.println("Encrypted Middle Chunk [" + encrMid.length + "]: " + new String(Hex.encode(encrMid)));

        byte[] decrMid = cabc.decrypt(encrMid, iv, streamOffset);
        System.out.println("Decrypted Middle Chunk [" + decrMid.length + "]: " + new String(Hex.encode(decrMid)));

        String mid = new String(decrMid, "UTF-8");
        System.out.println("Mid[" + mid.length() + "]: " + mid);

        assertEquals(input.substring(10, 20), mid);
    }

}
