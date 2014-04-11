package server;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;

import database.DatabaseConnector;
import dto.UserDto;
import dto.Validator;
import dto.VoteDto;

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
	}
	public Validator checkSignature(String sig, String encVote, int userId) {
		//TODO remove the DatabaseConnector from here
		
		DatabaseConnector dbc = new DatabaseConnector();
		
		UserDto userDto = new UserDto();
		userDto.setUserId(userId);
		
		byte[] pk = (byte[]) dbc.selectUserPublicKey(userDto).getObject();
		Validator val = new Validator();
		val.setVerified(false);
		if (pk == null) {
			val.setStatus("No public key available");
			return val;
		}
		byte[] signature = hexStringtoByteArray(sig);
		byte[] encVoteBytes=hexStringtoByteArray(encVote);
		try {
			EncodedKeySpec pubKeySpec=new X509EncodedKeySpec(pk);
			PublicKey PK = KeyFactory.getInstance("RSA").generatePublic(pubKeySpec);
			Signature ver = Signature.getInstance("SHA256WITHRSA");
			ver.initVerify(PK);
			ver.update(encVoteBytes);
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

	public Validator checkSignature(VoteDto voteDto) {
		return checkSignature(voteDto.getVoteSignature() , voteDto.getVoteEncrypted(), voteDto.getUserId());
	}

	public byte[] hexStringtoByteArray(String hex) {
		int len = hex.length();
		byte[] data = new byte[0];
		if (len % 2 == 0) {
			data = new byte[len / 2];
			for (int i = 0; i < len; i += 2) {
				data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character
						.digit(hex.charAt(i + 1), 16));
			}
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


	public Validator decryptVote(String ciph, PrivateKey privateKey) {
		Validator vRes = new Validator();
		byte[] ct = hexStringtoByteArray(ciph);
		
		try {
			Cipher dec = Cipher.getInstance("RSA");
			dec.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] plain = dec.doFinal(ct);
			String plaintext = byteArraytoHex(plain);

			byte[] plain2=hexStringtoByteArray(plaintext);
			String id=new String(plain2);
			int cand_id = Integer.parseInt(id);
			
			vRes.setVerified(true);
			vRes.setObject(cand_id);
		} catch (Exception ex) {
			vRes.setVerified(false);
			vRes.setStatus("Could not decrypt the vote");			
		}
		
		return vRes;
	}

	
	
	
	public String decrypt(String ciph, String password, int electionId) {
		byte[] ct = hexStringtoByteArray(ciph);
		String out = "";

		try {
			DatabaseConnector dbc=new DatabaseConnector();
			Validator val=dbc.getPrivateKey(electionId);
			if(val.isVerified()){
				byte[] decKey=DataEncryptor.AESDecrypt((byte[])val.getObject(), password);
				KeyFactory kf=KeyFactory.getInstance("RSA");
				PKCS8EncodedKeySpec ks=new PKCS8EncodedKeySpec(decKey);
				PrivateKey priv = kf.generatePrivate(ks);
				Cipher dec = Cipher.getInstance("RSA");
				dec.init(Cipher.DECRYPT_MODE, priv);
				byte[] plain = dec.doFinal(ct);
				String plaintext = byteArraytoHex(plain);				
				out = plaintext;
			}
		} catch (Exception ex) {
			Logger lgr = Logger.getLogger(SecurityValidator.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			out = "";
		}
		
		return out;
	}
	
	public Validator generateKeyPair(){
		Validator val=new Validator();
		try{
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(3072);
			KeyPair keyPair = gen.generateKeyPair();
			PublicKey K = keyPair.getPublic();
			PrivateKey k = keyPair.getPrivate();
			byte[] publicEncoded=K.getEncoded();
			byte[] privateEncoded=k.getEncoded();
			ArrayList<byte[]> keys=new ArrayList<byte[]>();
			keys.add(publicEncoded);
			keys.add(privateEncoded);
			val.setObject(keys);
			val.setVerified(true);
			val.setStatus("Keys successfully generated");
		}
		catch(Exception e){
			val.setVerified(false);
			val.setStatus("Failed to generate keys");
		}
		return val;
	}
}
