/**
 * @author Ahmad Kouraiem
 */
package server;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import dto.Validator;

public class RSAKeys {

	private PublicKey pubKey;
	private byte [] protectedPrivateKey; 

	String messageSubject = "Your voting private key";
			
	String messageBody = "Dear Certus User,\n"
						+ "Please find your protected private key as an attachment file to this email, "
						+ "don't forget to protect your key!";
	
	String attachmentFileName = "Certus private key";
	
	
	public void generateKeys(String password){
		try {			
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(3072);
			KeyPair keyPair = gen.generateKeyPair();
			pubKey = keyPair.getPublic();
			PrivateKey pvkKey = keyPair.getPrivate();
			byte[] plainPvkBytes = pvkKey.getEncoded();
			protectedPrivateKey = DataEncryptor.AESEncrypt(plainPvkBytes, password);
			
		} catch (Exception e) {
			e.printStackTrace();
		}

		return;
	}
	
	public PublicKey getPublicKey(){
		return pubKey;
	}
	
	public byte [] getProtectedPrivateKey(){
		return protectedPrivateKey;
	}
	
	public void writePublicKey(String filePath){
		try {
			writeFile(filePath, pubKey.getEncoded());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void writeProtectedPrivateKey(String filePath){
		try {
			writeFile(filePath, protectedPrivateKey);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void sendProtectedPrivateKey(String recepientAddress){
		EmailExchanger.sendEmailWithAttachement(recepientAddress, messageSubject, messageBody, protectedPrivateKey, attachmentFileName);
	}
	
	private static void writeFile (String path, byte [] content) throws IOException{
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(path));
		bos.write(content);
		bos.flush();
		bos.close();
	}	
	
	public static Validator getPrivateKey (byte[] encodedPrivateKey){
		Validator vKey = new Validator();
		
		try {
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
					encodedPrivateKey);
			KeyFactory generator = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = generator.generatePrivate(privateKeySpec);

			vKey.setVerified(true);
			vKey.setObject(privateKey);
		} catch (Exception e) {
			vKey.setVerified(false);
			vKey.setStatus("Convertion of bytes to private key failed");
		}
		
		return vKey;
	}
	
	public static boolean isValidPublicKey(byte[] key){
		boolean res = false;
		
		try {
			
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key);
	        KeyFactory generator = KeyFactory.getInstance("RSA");
	        generator.generatePublic(publicKeySpec);
			res = true;
		} catch (Exception e) {
			res = false;
		}		
		
		return res;
	}
}
