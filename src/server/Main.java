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
		
		//System.out.println(u.toString());
		ClientsSessions cs = new ClientsSessions();
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
			
			Validator verified=sec.checkSignature("018215E0BFD3AE13143206F74705267417AB56433802"
					+ "52DF7C7ACB78C2963F34A7B13E19DA23F2611DA417100F5D0C9F88C03565B2D6CB1C66"
					+ "FF831BF6A96BEF988013DB23E5DC682FDC290280EF941718694D90EFBE6916FC43A37C"
					+ "B2A49E5D85AD5EEF4A235378A65F9C00590B18F040732E207E0B897D335F374F958A39"
					+ "CD839D5029E6CB6AFFC922CAE32E4E9740311AD4BB12E8BE2EA8FB88C03ECBE614A32D"
					+ "B17AADE6A98AADF83ABDFB3A1C349F411DA097047D075F47F5E7D06019468F2839AC71"
					+ "2A6EE21FC46F26BF9C32502A975D21889C09DC9C5F9446E7FCE17BD5B84A064EE9AE2C"
					+ "8A08D97071160E313D783E73532B08398E72F28BBAA9F0CE19C27DB80672E3F3097FA7"
					+ "171F6F9CA9E2897C032C610ADEBBAC5A9CAF94459FF800889D21775A339CE648A16E42"
					+ "E915C0A8997B6E337BF6DE5D5F76C3E6C3D3662F16311E8684B04DB4B0EF39C9CA8E17"
					+ "1C8D3E9A3DDB190BBDAAA0F7C4DB896F42B453A8D8FA63CAC77E5AB663F640A0644802"
					+ "6150EBA7E11E4BB88D80363E", 
					"0154dad6e48a7462b1b0c7c764ab3dc9a560b7e2a10c175672e7e3feb54b9957833eea25f"
					+ "517c1a3274086a85c7077d7728833cce99d29b0a4ad25bd63a7a1fc875bb4ada80581a7"
					+ "8aaa5deddf1b200358b9530bec62a940e5fce91a93b605643609741480debc017a7f574"
					+ "9f512f6c6006e6ffa76887bfe5d68670f656a9dbae9ca4db86310b41c4833934f04ac14"
					+ "5d64944aa56a14a00c0f2d18d1bcfb53d39a4503c9609996c2a83244621068520a2b3b2"
					+ "7e3cc052aa9cdda9e9423e8416e7becb6c28076a72d9bf46f5bc740ef3af5039bc92fce"
					+ "38eb3ade5decbba1a88e4f7dd7c19067f015e837ecb77062fd5de17bdf172123cbb2d7a5"
					+ "ec3276d7588e", 1);
			if(verified.isVerified())
				System.out.println("Signature verified");
			else
				System.out.println(verified.getStatus());
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
