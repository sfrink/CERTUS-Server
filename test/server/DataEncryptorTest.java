package server;

import static org.junit.Assert.*;

import javax.xml.crypto.Data;

import org.junit.Test;

public class DataEncryptorTest {


	@Test
	public void test() {
		String text = "This is the most important message ever";
		String password = "YourPassword";
		String plainText = "";
		
		byte[] encryptedBytes;
		try {
			encryptedBytes = DataEncryptor.AESEncrypt(text.getBytes(), password);
			plainText = new String (DataEncryptor.AESDecrypt(encryptedBytes, password));
			assertEquals(text, plainText);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
