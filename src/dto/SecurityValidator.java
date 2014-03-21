package dto;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import database.DatabaseConnector;


public class SecurityValidator {

	public Validator checkSignature(String sig, int user_id){
		DatabaseConnector dbc=new DatabaseConnector();
		String pk=dbc.getPubKeyByUserID(user_id);
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
	
}
