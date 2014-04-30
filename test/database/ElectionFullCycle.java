package database;

import static org.junit.Assert.*;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import database.DatabaseConnector;
import dto.CandidateDto;
import dto.ElectionDto;
import dto.UserDto;
import dto.Validator;
import dto.VoteDto;
import enumeration.ElectionStatus;
import enumeration.ElectionType;
import rmi.CertusServer;
import server.SecurityValidator;

public class ElectionFullCycle
{

	private DatabaseConnector dbc = new DatabaseConnector();
	
	public ElectionFullCycle()
	{
		
	}
	
	
	@Test
	public void testPublicElection() throws Exception{
		int newPublicElectionId = testAddPublicElection();
		testEditPublicElection(newPublicElectionId);
		testopenElectionAndPopulateCandidates(newPublicElectionId);	

		testgotAccessToPublicElection(newPublicElectionId);
		testCloseElection(newPublicElectionId);
		testReopenElection(newPublicElectionId);
		testVoteForFirstCandidate(newPublicElectionId, "hirosh@gwmail.gwu.edu");
		testVoteForFirstCandidate(newPublicElectionId, "hirosh@gwmail.gwu.edu");
		testVoteProgressStatusForElection(newPublicElectionId);
		testCloseElection(newPublicElectionId);
		testPublishElectionResults(newPublicElectionId);
		testGetPublishedElections();
		testGetElectionResults(newPublicElectionId);
		testArchiveElection(newPublicElectionId);
		
	}
	@Test
	public void testPrivateElection() throws Exception{
		int newPrivateElectionId = testAddPrivateElection();
		testEditPrivateElection(newPrivateElectionId);
		testopenElectionAndPopulateCandidates(newPrivateElectionId);
		testAddAdditionalUsers(newPrivateElectionId);
		
		testgotAccessToPrivateElection(newPrivateElectionId);
		
		testgotAccessToPublicElection(newPrivateElectionId);
		testCloseElection(newPrivateElectionId);
		testReopenElection(newPrivateElectionId);
		testVoteForFirstCandidate(newPrivateElectionId, "hirosh@gwmail.gwu.edu");
		testVoteForFirstCandidate(newPrivateElectionId, "hirosh@gwmail.gwu.edu");
		testVoteProgressStatusForElection(newPrivateElectionId);
		testCloseElection(newPrivateElectionId);
		testPublishElectionResults(newPrivateElectionId);
		testGetPublishedElections();
		testGetElectionResults(newPrivateElectionId);
		testArchiveElection(newPrivateElectionId);
	}
	
	
	
	public int testAddPublicElection() throws RemoteException, Exception{
		int ownerId = 2;
		int newPublicElectionId = 0;
		ElectionDto election = new ElectionDto();
		
		election.setElectionName("automated test PUBLIC election name");
		election.setElectionDescription("automated test PUBLIC election description");
		election.setCandidatesListString("automated test 1 \nautomated test 2");
		election.setOwnerId(ownerId);
		election.setPassword("junit");
		Timestamp start = new Timestamp(System.currentTimeMillis());
		election.setStartDatetime(start.toString());
		
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(start);
		calendar.add(Calendar.DAY_OF_WEEK, 7);
		Timestamp close = new Timestamp(calendar.getTimeInMillis());
		election.setCloseDatetime(close.toString());
		
		election.setElectionType(ElectionType.PUBLIC.getCode());
		election.setEmailList("hirosh@gwmail.gwu.edu\ndkarmazi@gwu.edu\n");
		System.out.println("adding public election :"+  election.toString());
		
		
		Validator val = dbc.addElection(election);
		
		if (val.isVerified()) {
			ElectionDto electionAdded = (ElectionDto)val.getObject();
			newPublicElectionId = electionAdded.getElectionId();
		}
		
		assertTrue("add election", val.isVerified());
		return newPublicElectionId;
	}
	
	
	public void testEditPublicElection(int newPublicElectionId) throws RemoteException{
		ElectionDto election = new ElectionDto();
		
		Validator vElection = dbc.selectElectionForOwner(newPublicElectionId);
		if (vElection.isVerified()){
			election = (ElectionDto)vElection.getObject();
		}
		
		election.setElectionName("automated test PUBLIC election name modified");
		election.setElectionDescription("automated test PUBLIC election description modified");
		election.setCandidatesListString("public candidate A \npublic candidate B\npublic candidate C\n");
		election.setEmailList("hirosh@gwmail.gwu.edu\ndkarmazi@gwu.edu\nsulochane@yahoo.com");
		Validator val = dbc.editElection(election);
		
		if (val.isVerified()) {
			ElectionDto electionEdited = (ElectionDto)val.getObject();
			System.out.println("Election failed to edit : \n" + electionEdited.toString());
		}
		assertTrue("edit election", val.isVerified());
		
	}
	
	public void testopenElectionAndPopulateCandidates(int electionId)  throws RemoteException{
		Validator val = dbc.openElectionAndPopulateCandidates(electionId);
		assertTrue("open election", val.isVerified());
	}
	
	public void testgotAccessToPublicElection(int electionId) {
		UserDto u = dbc.selectUserByEmailLimited("hirosh@gwmail.gwu.edu");
		
		boolean hasAccess = dbc.gotAccessToElection(u.getUserId(), electionId);
		assertTrue("access to public election (registered user)", hasAccess);
		
		
	}
	public void testgotAccessToPrivateElection(int electionId) {
		UserDto u = dbc.selectUserByEmailLimited("hirosh@gwmail.gwu.edu");
		
		boolean hasAccess = dbc.gotAccessToElection(u.getUserId(), electionId);
		assertTrue("access to private election (registered user)", hasAccess);
		
		//u = dbc.selectUserByEmailLimited("sfrink1@gmail.com");
		//hasAccess = dbc.gotAccessToElection(u.getUserId(), electionId);
		//assertFalse("access to private election (uninvited user)", hasAccess);
		
		String email = "newman" + electionId + "@somewhere.com";
		u = dbc.selectUserByEmailLimited(email);
		hasAccess = dbc.isInvited(u.getUserId(), electionId);
		assertTrue("access to private election (invited user)", hasAccess);
		
		
	}
	
	public int testAddPrivateElection(){
		int newPrivateElectionId = 0;
		int ownerId = 2;
		ElectionDto election = new ElectionDto();
		
		election.setElectionName("automated test PRIVATE election name");
		election.setElectionDescription("automated test PRIVATE election description");
		election.setCandidatesListString("private candidate A \nprivate candidate B\nprivate candidate C\n");
		election.setOwnerId(ownerId);
		election.setPassword("junit");
		Timestamp start = new Timestamp(System.currentTimeMillis());
		election.setStartDatetime(start.toString());
		
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(start);
		calendar.add(Calendar.DAY_OF_WEEK, 7);
		Timestamp close = new Timestamp(calendar.getTimeInMillis());
		election.setCloseDatetime(close.toString());
		
		election.setElectionType(ElectionType.PRIVATE.getCode());
		election.setEmailList("hirosh@gwmail.gwu.edu\ndkarmazi@gwu.edu\n");
		System.out.println("adding private election :"+ election.toString());
		
		
		Validator val = dbc.addElection(election);
		
		if (val.isVerified()) {
			ElectionDto electionAdded = (ElectionDto)val.getObject();
			newPrivateElectionId = electionAdded.getElectionId();
		}
		
		assertTrue("add election", val.isVerified());
		return newPrivateElectionId;
	}
	
	public void testEditPrivateElection(int newPrivateElectionId) throws RemoteException{
		ElectionDto election = new ElectionDto();
		Validator vElection = dbc.selectElectionForOwner(newPrivateElectionId);
		if (vElection.isVerified()){
			election = (ElectionDto)vElection.getObject();
		}
		
		
		election.setElectionName("automated test PRIVATE election name modified");
		election.setElectionDescription("automated test PRIVATE election description modified");
		election.setCandidatesListString("private candidate AA \nprivate candidate BB\nprivate candidate CC\n");
		election.setEmailList("hirosh@gwmail.gwu.edu\ndkarmazi@gwu.edu\n");
		String newEmail = "somebody" + newPrivateElectionId + "@somewhere.com\n";
		newEmail += "somebody_"+ newPrivateElectionId + "@somewhere.com\n";
		election.setEmailListInvited(newEmail);
		Validator val = dbc.editElection(election);
		
		if (val.isVerified()) {
			ElectionDto electionEdited = (ElectionDto)val.getObject();
			System.out.println("Election failed to edit : \n" + electionEdited.toString());
			//newPrivateElectionId = electionAdded.getElectionId();
		}
		assertTrue("edit election", val.isVerified());
	}

	public void testAddAdditionalUsers(int electionId)  throws RemoteException{
		
		ElectionDto electionDto = new ElectionDto();
		
		electionDto.setElectionId(electionId);
		
		electionDto.setEmailList("sulochane@gmail.com");
		String newEmail = "newman" + electionId + "@somewhere.com\n";
		newEmail += "newman_"+ electionId + "@somewhere.com\n";
		electionDto.setEmailListInvited(newEmail);
		Validator val = dbc.addAdditionalUsersToElection(electionDto);
		assertTrue("add additional users to election ", val.isVerified());
	}

	public void testVoteForFirstCandidate(int electionId, String email){
		Validator val = dbc.selectElectionFullDetail(electionId);
		
		ElectionDto electionDto = (ElectionDto)val.getObject();
		ArrayList<CandidateDto> candidates = electionDto.getCandidateList();
		if (!candidates.isEmpty()){
			int firstCandidate = candidates.get(0).getCandidateId();
			
			// get user id
			UserDto u = dbc.selectUserByEmailLimited(email);
			
			// vote for the first candidate
			Validator vPubKey = dbc.getTallierPublicKey(electionId);
			if (vPubKey.isVerified()){
				
				PublicKey publicKey = (PublicKey) vPubKey.getObject();	// get public key
				String plaintext = Integer.toString(firstCandidate);	// prepare plaintext
				byte[] plainBytes = plaintext.getBytes();
				
				try {
					// Encrypt the vote
					Cipher enc = Cipher.getInstance("RSA");					// init RSA Cipher
					enc.init(Cipher.ENCRYPT_MODE, publicKey);			
					byte[] cipherBytes= enc.doFinal(plainBytes);			// encrypt
					String encryptedVote = SecurityValidator.byteArraytoHex(cipherBytes); // convert to Hex
					
					// sign vote
					String voteSignature = "";
					//String encryptedVote = txtVote.getText(); 
					byte [] encryptedVoteBytes = HexToByte(encryptedVote);
					byte [] signature = null;
					signature = Sign(encryptedVoteBytes);
					String hexSignature = ByteToHex(signature);
					
					// Cast the vote
					VoteDto voteDto = new VoteDto();
					voteDto.setElectionId(electionId);
					voteDto.setUserId(u.getUserId());
					voteDto.setVoteEncrypted(encryptedVote);
					voteDto.setVoteSignature(hexSignature);
					Validator vVote = dbc.vote(voteDto);
					
					if (!vVote.isVerified()){
						System.out.println("vote :"+ vVote.toString());
					}
				
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				} catch (NoSuchPaddingException e) {
					e.printStackTrace();
				} catch (BadPaddingException e) {
					e.printStackTrace(); 
				} catch (IllegalBlockSizeException e) {
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					e.printStackTrace();
				}					
			}
		}
	}
	
	private  PrivateKey getPrivateKey (byte[] encodedPrivateKey){
		try {
	        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
	        KeyFactory generator = KeyFactory.getInstance("RSA");
	        PrivateKey privateKey = generator.generatePrivate(privateKeySpec);

	        return privateKey;
	    } catch (Exception e) {
	        throw new IllegalArgumentException("Failed to create key from provided encoded key", e);
	    }
	}

	private  byte[] Sign (byte[] encryptedVote){
		String privateKeyFilePath = "/Users/sulo/gwu/study/4-csci6908-Research/data/keys/hirosh@gwmail.gwu.edu/Certus private key";
		File privateKeyFile = new File(privateKeyFilePath);
		String password = "test"; // private key file password
		byte[] signature = null;
		if (privateKeyFile.exists()){
			
			
			byte [] encryptedPVK = new byte[(int)privateKeyFile.length()];
			DataInputStream fileST;
			try {
				fileST = new DataInputStream((new FileInputStream(privateKeyFile)));
				fileST.readFully(encryptedPVK);
				fileST.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			
			Cipher cipher;
			try {
				cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
				String encryptionKey = generateKey(password, 10000);
				String IV = generateKey(password, 9000);
				SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes(), "AES");
				cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
				byte[] encodedPrivateKey = cipher.doFinal(encryptedPVK);
			
			
				Signature sign = Signature.getInstance("SHA256WITHRSA");
				PrivateKey prvtKey = getPrivateKey(encodedPrivateKey);
				
				sign.initSign(prvtKey);
				sign.update(encryptedVote);   
				
				System.out.println("Message has been signed.");
	
				signature =  sign.sign();
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				e1.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			}

		}
		return signature;
	}
	
	private static byte[] HexToByte (String Hex){
		return DatatypeConverter.parseHexBinary(Hex);
	}
	
	private static String ByteToHex (byte[] Bin){
		return DatatypeConverter.printHexBinary(Bin);
		
	}
	private  String generateKey (String password, int iterations) throws Exception{

		int derivedKeyLength = 64;
	    SecretKey cipherKey = null;
		
		String algorithm = "PBKDF2WithHmacSHA1";
	    SecretKeyFactory factory = null;

		factory = SecretKeyFactory.getInstance(algorithm);
	    
	    // create salt
	    byte[] salt = password.getBytes();

	    // create cipher key
	    PBEKeySpec cipherSpec = new PBEKeySpec(password.toCharArray(), salt, iterations, derivedKeyLength);

		cipherKey = factory.generateSecret(cipherSpec);

	    cipherSpec.clearPassword();
		return DatatypeConverter.printHexBinary(cipherKey.getEncoded());
		
	}
	
	public void testVoteProgressStatusForElection(int electionId) {
		Validator val = dbc.voteProgressStatusForElection(electionId);
		assertTrue("vote progress", val.isVerified());
		
	}
	
	public void testCloseElection(int electionId){
		Validator val = dbc.editElectionStatus(electionId, ElectionStatus.CLOSED);
		assertTrue("close election", val.isVerified());
	}
	
	public void testReopenElection(int electionId){
		Validator val = dbc.editElectionStatus(electionId, ElectionStatus.OPEN);
		assertTrue("reopen election", val.isVerified());
	}
	
	public void testPublishElectionResults(int electionId){
		Validator val = dbc.publishResults(electionId, "junit");
		assertTrue("publish election", val.isVerified());
	}
	
	public void testGetPublishedElections(){
		UserDto u = dbc.selectUserByEmailLimited("hirosh@gwmail.gwu.edu");
		
		Validator val = dbc.selectElectionsForResults(u.getUserId());
		assertTrue("published elections", val.isVerified());
	}
	public void testGetElectionResults(int electionId){
		Validator val = dbc.selectResults(electionId);
		assertTrue("election result", val.isVerified());
	}

	public void testArchiveElection(int electionId){
		
		Validator val = dbc.deleteElection(electionId);
		assertTrue("archive election", val.isVerified());
	}
}
