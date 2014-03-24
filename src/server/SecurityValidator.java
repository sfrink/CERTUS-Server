package server;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;

import database.DatabaseConnector;
import dto.UserDto;
import dto.Validator;

public class SecurityValidator {
	
	private static String securityKeyBasePath;
	private static String securityKeystoreAlias;
	private static String securityKeystorePassword;
	private static String securityKeystoreFile;
	private static String securityKeystorePrivatekey;
	
	public SecurityValidator()
	{
		securityKeyBasePath = ConfigurationProperties.securityKeyBasePath();
		securityKeystoreAlias = ConfigurationProperties.securityKeystoreTallierAllias();
		securityKeystorePassword = ConfigurationProperties.securityKeystoreTallierPassword();
		securityKeystoreFile = securityKeyBasePath + ConfigurationProperties.securityKeystoreTallierFile();
		securityKeystorePrivatekey = securityKeyBasePath + ConfigurationProperties.securityKeystoreTallierPrivatekey();
		
		System.out.println(securityKeystoreFile);
		System.out.println(securityKeystorePrivatekey);
		System.out.println(securityKeystorePassword);
		System.out.println(securityKeystoreAlias);
	}
	public Validator checkSignature(String sig, int userId) {
		//TODO remove the DatabaseConnector from here
		
		DatabaseConnector dbc = new DatabaseConnector();
		
		UserDto userDto = new UserDto();
		userDto.setUserId(userId);
		
		String pk = (String) dbc.selectUserPublicKey(userDto).getObject();
		Validator val = new Validator();
		val.setVerified(false);
		if (pk == null) {
			val.setStatus("No public key available");
			return val;
		}
		byte[] pubKey = hexStringtoByteArray(pk);
		byte[] signature = hexStringtoByteArray(sig);
		try {
			PublicKey PK = KeyFactory.getInstance("RSA").generatePublic(
					new X509EncodedKeySpec(pubKey));
			Signature ver = Signature.getInstance("SHA256WITHRSA");
			ver.initVerify(PK);
			ver.update(signature);
			val.setVerified(ver.verify(signature));
			if (val.isVerified())
				val.setStatus("Signature verified");
			else
				val.setStatus("Signature did not verify");
			return val;
		} catch (Exception ex) {
			Logger lgr = Logger.getLogger(SecurityValidator.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		return val;
	}

	public byte[] hexStringtoByteArray(String hex) {
		int len = hex.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character
					.digit(hex.charAt(i + 1), 16));
		}
		return data;
	}

	public static String byteArraytoHex(byte[] arr) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < arr.length; i++) {
			sb.append(Integer.toString((arr[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return sb.toString();
	}

	public String decrypt(String ciph) {
		byte[] ct = hexStringtoByteArray(ciph);
		try {
			PrivateKey priv = getPrivateKey();
			Cipher dec = Cipher.getInstance("RSA");
			dec.init(Cipher.DECRYPT_MODE, priv);
			byte[] plain = dec.doFinal(ct);
			String plaintext = byteArraytoHex(plain);
			return plaintext;
		} catch (Exception ex) {
			Logger lgr = Logger.getLogger(SecurityValidator.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		return null;
	}

	public PrivateKey getPrivateKey() {
		KeyStore ks;
		try {
			ks = KeyStore.getInstance("PKCS12");

			// get user password and file input stream
			char[] password = securityKeystorePassword.toCharArray();

			java.io.FileInputStream fis = null;
			try {
				fis = new java.io.FileInputStream(securityKeystorePrivatekey);
				ks.load(fis, password);
			} finally {
				if (fis != null) {
					fis.close();
				}
			}
			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
					password);

			// get my private key
			KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks
					.getEntry(securityKeystoreAlias, protParam);
			PrivateKey myPrivateKey = pkEntry.getPrivateKey();
			return myPrivateKey;

		} catch (Exception ex) {
			Logger lgr = Logger.getLogger(SecurityValidator.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			return null;
		}
	}
	
	public Validator getTallierPublicKey(){
		Validator val=new Validator();
    	try{
	    	FileInputStream is = new FileInputStream(securityKeystoreFile);
	
	        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	        keystore.load(is, securityKeystorePassword.toCharArray());
	
	
	
	        Key key = keystore.getKey(securityKeystoreAlias, securityKeystorePassword.toCharArray());
	        if (key instanceof PrivateKey) {
	          // Get certificate of public key
	          Certificate cert = keystore.getCertificate(securityKeystoreAlias);
	
	          // Get public key
	          PublicKey publicKey = cert.getPublicKey();
	          val.setVerified(true);
	          val.setStatus("Retrieved public key");
	          val.setObject(publicKey);
	          return val;
	          
	        }
	        else{
	        	val.setVerified(false);
	        	val.setStatus("Failed to retrieve public key");
	        	return val;
	        }
    	}
    	catch(Exception ex){
    		Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			val.setStatus("Error occured");
			val.setVerified(false);
			return val;
    	}
	}
}
