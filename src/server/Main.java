package server;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Iterator;

import javax.crypto.Cipher;

import rmi.CertusServer;
import database.DatabaseConnector;
import dto.*;
import enumeration.*;


public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		DatabaseConnector db = new DatabaseConnector();
		
		UserDto u = db.selectUserById(1);
		
		System.out.println(u.toString());
		
		Validator v = db.checkIfUsernamePasswordMatch("user@certus.org", "password");
		System.out.println(v.getStatus());
		
		// Retrive Elections
		/*ElectionDto electionDto = db.selectElection(1);
		System.out.println(electionDto.toString());
		
		for (ElectionDto e : db.selectElections(ElectionStatus.NEW)) {
			System.out.println(e.toString());
		}

		// Retrieve Candidates
		CandidateDto candidateDto = db.selectCandidate(1);
		System.out.println(candidateDto.toString());
		
		for (CandidateDto c : db.selectCandidatesOfElection(1)) {
			System.out.println(c.toString());
		}*/
		try {
			CertusServer serv=new CertusServer();
			PublicKey pk=(PublicKey)serv.getTallierPublicKey().getObject();
			System.out.println(pk.toString());
			Cipher enc = Cipher.getInstance("RSA");
			  // Note 1:  "ECB" in line above is bogus.  Doesn't actually encrypt
			  //   more than one block.
			  // Note 2:  Encoding function above is OAEP.
			enc.init(Cipher.ENCRYPT_MODE, pk);
			String m1 = "Attack at dawn"; 
			byte[] b1 = m1.getBytes();   
			byte[] c = enc.doFinal(b1);
			SecurityValidator sec=new SecurityValidator();
			PrivateKey sk=sec.getPrivateKey();
			System.out.println(sk.toString());
			String hex=sec.byteArraytoHex(c);
			String pt=sec.decrypt(hex);
			byte[] plain=sec.hexStringtoByteArray(pt);
			String message=new String(plain);
			System.out.println(message);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
