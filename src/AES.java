import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import static org.apache.commons.codec.binary.Hex.*;

/**
 * Created by jay on 11/01/16.
 */
interface AES {


    static String readEncrypted(){

        try {
            File encryptedFile = new File("/home/jay/Desktop/encrypted.txt");
            File ivFile = new File("/home/jay/Desktop/iv.txt");
            FileReader fr;

            // The IV (Initialisation vector has to be read byte-by-byte (16 bytes)
            byte[] iv = new byte[16];
            DataInputStream dis = null;
            dis = new DataInputStream(new FileInputStream(ivFile));
            dis.readFully(iv);

            // During the encryption process, the cipher text was encoded in base64 before writing to file.
            // Hence, the read string has to be decoded in order for us to get the original cipher text.
            fr = new FileReader(encryptedFile);
            BufferedReader br = new BufferedReader(fr);
            byte[] cipherText = Base64.decodeBase64(br.readLine());
            String secretKey = br.readLine();

            // in order for us to store the secret key to file, it was converted to hex prior to writing to file.
            // decoding the hex is needed for us to get the original secret key.
            byte[] encoded;
            encoded = decodeHex(secretKey.toCharArray());

            // need to create SecretKeySpec and IvParameterSpec in order to decrypt.
            SecretKeySpec skeyspec = new SecretKeySpec(encoded, "AES");
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            //System.out.println(cipherText +"\n" + secretKey);

            // initialising decryption cypher
            Cipher aesCipherForDecryption = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            aesCipherForDecryption.init(Cipher.DECRYPT_MODE, skeyspec, ivspec);

            byte[] byteDecryptedText = aesCipherForDecryption.doFinal(cipherText);
            String decryptedPassword = new String(byteDecryptedText);
            //System.out.println(decryptedPassword);
            return decryptedPassword;


        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (DecoderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }
}
