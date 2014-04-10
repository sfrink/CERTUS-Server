package server;

import static org.junit.Assert.*;

import java.security.PublicKey;

import javax.crypto.Cipher;

import org.junit.Test;

import database.DatabaseConnector;
import dto.ElectionDto;
import dto.Validator;
import rmi.CertusServer;

public class Crypto
{

	@Test
	public void testEncrypt() {
		
		
		try {
		
			DatabaseConnector dbc = new DatabaseConnector();

			int electionId = 70;
			
			PublicKey publicKey = (PublicKey)(dbc.getTallierPublicKey(electionId).getObject());
			System.out.println(publicKey.toString());
			
			byte[] PrivateKey = (byte[])(dbc.getPrivateKey(electionId).getObject()); 
			System.out.println(PrivateKey.toString());
			
			Cipher enc = Cipher.getInstance("RSA");
			enc.init(Cipher.ENCRYPT_MODE, publicKey);
			
			String m1 = "This is plain text"; 
			byte[] plainBytes = m1.getBytes();   
			byte[] cipherBytes = enc.doFinal(plainBytes);
			
			String cipherText = SecurityValidator.byteArraytoHex(cipherBytes);
			System.out.println("Cipher text : " + cipherText);

			assertTrue("encryption pass", true);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			
			assertTrue("encryption pass", false);
		}
		
		
		
	}

	
}
