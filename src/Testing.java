import sun.misc.BASE64Encoder;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import static org.apache.commons.codec.binary.Hex.*;
import static org.apache.commons.io.FileUtils.*;

/**
 * Created by jay on 7/01/16.
 */
public class Testing {

    String pass;
    byte[] iv;
    SecureRandom prng;
    IvParameterSpec ivspec;
    Cipher aesCipherForEncryption;
    byte[] bytePassToEncrypt;
    byte[] cipherText;
    String strCipherText = new String();
    SecretKeySpec skeySpec;
    byte[] key;
    SecretKey secretKey;


    public static void main(String[] args) {

        String password = AES.readEncrypted();
        System.out.println(password);
        // do https request after this ->

    }

    // The following methods were used to encrypt the passwords and store them to a file. They were only used once to encrypt the passwords the first time.
    // Kept here for future reference.
    public void getCredentials() {

        String filePath = "/home/jay/Desktop/pass.txt";

        try {
            FileReader fr = new FileReader(filePath);
            BufferedReader br = new BufferedReader(fr);
            // possibly not a good idea to read the file in as plain text. A solution could be to read already encrypted credentials and decrypt them

            pass = br.readLine();


        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

            // creating the keygen that will create an AES key with a length of 256 bits.
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            secretKey = keyGen.generateKey();
            key = secretKey.getEncoded();
            skeySpec = new SecretKeySpec(key, "AES");

            // creating an initialisation vector via PRNG
            iv = new byte[16];
            prng = new SecureRandom();
            prng.nextBytes(iv);
            ivspec = new IvParameterSpec(iv);
            encrypt();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    public void encrypt(){
        try {
            //creating a cipher
            aesCipherForEncryption = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec);
            bytePassToEncrypt = pass.getBytes();
            cipherText = aesCipherForEncryption.doFinal(bytePassToEncrypt);
            strCipherText = new BASE64Encoder().encode(cipherText);
            //System.out.println("Cipher text generated using AES is: " + strCipherText);
            File file = new File("/home/jay/Desktop/encrypted.txt");
            writeStringToFile(file, strCipherText + "\n", false);
            char[] hex = encodeHex(secretKey.getEncoded());


            writeStringToFile(file, String.valueOf(hex), true);
            writeByteArrayToFile(new File("/home/jay/Desktop/iv.txt"), iv, false);

        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
