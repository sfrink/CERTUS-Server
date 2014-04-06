/**
 * @author Ahmad Kouraiem
 */
package server;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

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
			
			System.out.println("RSA key pair are generated.");
			
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("RSA key pair generation failed");
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
	
	
}
