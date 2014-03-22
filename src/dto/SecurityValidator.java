package dto;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;

import database.DatabaseConnector;


public class SecurityValidator {

	public Validator checkSignature(String sig, int user_id){
		DatabaseConnector dbc=new DatabaseConnector();
		String pk=(String)dbc.getPubKeyByUserID(user_id).getObject();
		Validator val=new Validator();
		val.setVerified(false);
		if(pk==null){
			val.setStatus("No public key available");
			return val;
		}
		byte[] pubKey=hexStringtoByteArray(pk);
		byte[] signature=hexStringtoByteArray(sig);
		try{
			PublicKey PK=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKey));
			Signature ver=Signature.getInstance("SHA256WITHRSA");
			ver.initVerify(PK);
			ver.update(signature);
			val.setVerified(ver.verify(signature));
			if(val.isVerified())
				val.setStatus("Signature verified");
			else
				val.setStatus("Signature did not verify");
			return val;
		}
		catch(Exception ex){
			Logger lgr = Logger.getLogger(SecurityValidator.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		return val;
	}
	
	public byte[] hexStringtoByteArray(String hex){
		 int len = hex.length();
		    byte[] data = new byte[len / 2];
		    for (int i = 0; i < len; i += 2) {
		        data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
		                             + Character.digit(hex.charAt(i+1), 16));
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
	
	public String decrypt(String ciph, String sk){
		byte[] secKey=hexStringtoByteArray(sk);
		byte[] ct=hexStringtoByteArray(ciph);
		try{
			PrivateKey priv=KeyFactory.getInstance("RSA").generatePrivate(new X509EncodedKeySpec(secKey));
			Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			dec.init(Cipher.DECRYPT_MODE, priv);
			byte[] plain=dec.doFinal(ct);
			String plaintext=byteArraytoHex(plain);
			return plaintext;
		}
		catch(Exception ex){
			Logger lgr = Logger.getLogger(SecurityValidator.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		return null;
	}
	
}
