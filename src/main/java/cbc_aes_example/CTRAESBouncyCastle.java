package cbc_aes_example;

import java.security.SecureRandom;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class CTRAESBouncyCastle {

    private final SICBlockCipher ctrCipher = new SICBlockCipher(new AESEngine());
    private final SecureRandom random = new SecureRandom();
    public final int blockSize = ctrCipher.getBlockSize();

    private KeyParameter key;

    public void setKey(byte[] key) {
        this.key = new KeyParameter(key);
    }

    public byte[] encrypt(byte[] input, byte[] iv, long streamOffset)
            throws DataLengthException, InvalidCipherTextException {
        return processing(input, true, iv, streamOffset);
    }

    public byte[] encrypt(byte[] input)
            throws DataLengthException, InvalidCipherTextException {
        byte[] iv = new byte[blockSize];
        random.nextBytes(iv);
        byte[] encrypted = processing(input, true, iv, 0);
        byte[] output = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(encrypted, 0, output, iv.length, encrypted.length);
        return output;
    }

    public byte[] decrypt(byte[] input, byte[] iv, long streamOffset)
            throws DataLengthException, InvalidCipherTextException {
        return processing(input, false, iv, streamOffset);
    }

    public byte[] decrypt(byte[] input)
            throws DataLengthException, InvalidCipherTextException {
        byte[] iv = new byte[blockSize];
        System.arraycopy(input, 0, iv, 0, iv.length);
        byte[] encrypted = new byte[input.length - iv.length];
        System.arraycopy(input, iv.length, encrypted, 0, encrypted.length);
        return processing(encrypted, true, iv, 0);
    }

    private byte[] processing(byte[] input, boolean encrypt, byte[] iv, long streamOffset)
            throws DataLengthException, InvalidCipherTextException {
        byte[] output = new byte[input.length];
        ctrCipher.init(encrypt, new ParametersWithIV(key, iv));
        ctrCipher.seekTo(streamOffset);
        ctrCipher.processBytes(input, 0, input.length, output, 0);
        return output;
    }

 }
