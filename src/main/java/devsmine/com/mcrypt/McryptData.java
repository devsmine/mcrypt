package devsmine.com.mcrypt;

import android.util.Base64;

import java.security.Key;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES encryption and decryption
 *
 * @author devsmine
 * @see Base64
 */


public class McryptData {

    //-----Category constant-----//
    /**
     * The default Initialization Vector is 16 Bits of 0
     */
    private static final IvParameterSpec DEFAULT_IV = new IvParameterSpec(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    /**
     * Encryption algorithm using AES
     */
    private static final String ALGORITHM = "AES";
    /**
     * AES uses CBC mode with PKCS5Padding
     */
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    //-----Member variables-----
    /**
     * Get the key of AES encryption and decryption
     */
    private Key key;
    /**
     * Initialization Vector used in AES CBC mode
     */
    private IvParameterSpec iv;
    /**
     * Cipher object
     */
    private Cipher cipher;

    /**
     * Constructor, using 128 Bits AES key (calculating MD5 of any length key) and preset IV
     *
     * @param key Pass in any length of AES key
     */
    public McryptData(final String key) {
        this(key, 128);
    }

    /**
     * Constructor, using 128 Bits or 256 Bits AES keys (calculating MD5 or SHA256 for any length key) and preset IV
     *
     * @param key Pass in any length of AES key
     * @param bit The length of the incoming AES key, the value can be 128, 256 (Bits)
     */
    public McryptData(final String key, final int bit) {
        this(key, bit, null);
    }

    /***
     * Constructor, use 128 Bits or 256 Bits AES key (calculate MD5 or SHA256 of any length key), calculate IV value with MD5
     * @param key Pass in any length of AES key
     * @param bit The length of the incoming AES key, the value can be 128, 256 (Bits)
     * @param iv Pass in an IV string of any length
     *
     ***/

    public McryptData(final String key, final int bit, final String iv) {
        if (bit == 256) {
            this.key = new SecretKeySpec(getHash("SHA-256", key), ALGORITHM);
        } else {
            this.key = new SecretKeySpec(getHash("MD5", key), ALGORITHM);
        }
        if (iv != null) {
            this.iv = new IvParameterSpec(getHash("MD5", iv));
        } else {
            this.iv = DEFAULT_IV;
        }

        init();
    }

    //-----object method-----
    /**
           * Get the hash value of the string
           *
           * @param algorithm incoming hash algorithm
           * @param text Pass in the string to be hashed
           * @return returns the content after hashing
           */
    private static byte[] getHash(final String algorithm, final String text) {
        try {
            return getHash(algorithm, text.getBytes("UTF-8"));
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /***
     *
     * Get the hash value of the data
     * @param algorithm incoming hash algorithm
     * @param data Pass in the data to be hashed
     * @return returns the content after hashing
     */
    private static byte[] getHash(final String algorithm, final byte[] data) {
        try {
            final MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.update(data);
            return digest.digest();
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * initialization
     */
    private void init() {
        try {
            cipher = Cipher.getInstance(TRANSFORMATION);
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * Encrypted text
     *
     * @param str Pass in the text to be encrypted
     * @return Return the encrypted text
     */
    public String encrypt(final String str) {
        try {
            return encrypt(str.getBytes("UTF-8"));
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     *
     * Encrypted data
     * @param data Pass in the data to be encrypted
     * @return returns the encrypted data
     */

    public String encrypt(final byte[] data) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            final byte[] encryptData = cipher.doFinal(data);
            return new String(Base64.encode(encryptData, Base64.DEFAULT), "UTF-8");
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * Decrypt text
     * @param str Pass in the text to be decrypted
     * @return returns the decrypted text
     */


    public String decrypt(final String str) {
        try {
            return decrypt(Base64.decode(str, Base64.DEFAULT));
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * Decrypt text
     *
     * @param data Pass in the data to be decrypted
     * @return returns the decrypted text
     */

    public String decrypt(final byte[] data) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            final byte[] decryptData = cipher.doFinal(data);
            return new String(decryptData, "UTF-8");
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    public static String encryptString(String content) {
        //Fill in the password and iv string here, pay attention to ensure 16-bit
        McryptData ea = new McryptData("****************", 128, "################");
        return ea.encrypt(content);
    }

    public static String decryptString(String content) {
        String result = null;
        try {
            //Fill in the password and iv string here, pay attention to ensure 16-bit
            McryptData ea = new McryptData("****************", 128, "################");
            result = ea.decrypt(content);
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return result;
    }
}

