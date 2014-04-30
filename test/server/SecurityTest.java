package server;

import static org.junit.Assert.*;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.Cipher;

import org.junit.Test;

import dto.Validator;

public class SecurityTest {

	SecurityValidator sec=new SecurityValidator();
	
	@Test
	public void KeyGenTest() {
		Validator v=sec.generateKeyPair();
		assertTrue("Generated keys", v.isVerified());
	}
	
	@Test
	public void decryptTest(){
		String plain="Attack at dawn";
		byte[] plainByte=plain.getBytes();
		try {
			Validator v=sec.generateKeyPair();
			if(v.isVerified()){
				ArrayList<byte[]> arr=(ArrayList<byte[]>)v.getObject();
				KeyFactory kf=KeyFactory.getInstance("RSA");
				PKCS8EncodedKeySpec ks1=new PKCS8EncodedKeySpec(arr.get(0));
				PKCS8EncodedKeySpec ks2=new PKCS8EncodedKeySpec(arr.get(1));
				PublicKey pub=kf.generatePublic(ks1);
				PrivateKey priv=kf.generatePrivate(ks2);
				Cipher enc = Cipher.getInstance("RSA");
				enc.init(Cipher.ENCRYPT_MODE, pub);
				byte[] ciph=enc.doFinal(plainByte);
				Validator vdec=sec.decryptVote(sec.byteArraytoHex(ciph), priv);
				String newPlain="";
				if(vdec.isVerified()){
					newPlain=new String(sec.hexStringtoByteArray((String)vdec.getObject()));
				}
				assertTrue("Enc and dec", newPlain==plain);
			}
		}
		catch(Exception e){
			assert(false);
		}
	}

}
