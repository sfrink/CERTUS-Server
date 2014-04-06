/**
 * @author Ahmad Kouraiem
 */
package server;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.xml.bind.DatatypeConverter;

public class DataEncryptor {
	
	static int keyIterations = 10000;
	static int ivItereations = 9000;
	
	public static byte[] AESEncrypt(byte[] plainText, String password) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		String encryptionKey = generateKey(password, keyIterations);
		String IV = generateKey(password, ivItereations);
		SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes(), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
		return cipher.doFinal(plainText);
	}

	public static byte[] AESDecrypt(byte[] cipherText, String password) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		String encryptionKey = generateKey(password, keyIterations);
		String IV = generateKey(password, ivItereations);
		SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes(), "AES");
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
		return cipher.doFinal(cipherText);
	}

	public static String generateKey (String password, int iterations) throws Exception{

		int derivedKeyLength = 64;
	    SecretKey cipherKey = null;
		
		String algorithm = "PBKDF2WithHmacSHA1";
	    SecretKeyFactory factory = null;

		factory = SecretKeyFactory.getInstance(algorithm);
	    
	    // create salt
	    byte[] salt = password.getBytes();

	    // create cipher key
	    PBEKeySpec cipherSpec = new PBEKeySpec(password.toCharArray(), salt, iterations, derivedKeyLength);

		cipherKey = factory.generateSecret(cipherSpec);

	    cipherSpec.clearPassword();
		return DatatypeConverter.printHexBinary(cipherKey.getEncoded());
		
	}

}
