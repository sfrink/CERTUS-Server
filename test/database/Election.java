package database;

import static org.junit.Assert.*;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Timer;

import org.junit.Test;

import dto.CandidateDto;
import dto.ElectionDto;
import dto.ElectionProgressDto;
import dto.Validator;
import enumeration.ElectionStatus;
import enumeration.ElectionType;

public class Election
{
	private DatabaseConnector dbc = new DatabaseConnector();

	
	@Test
	public void testSelectElection() {
		//ElectionDto election = new ElectionDto();
		
		int electionId = 26;
		//Validator val = dbc.selectElection(electionId);
		Validator val = dbc.selectElectionForOwner(electionId);
		assertTrue("select election", val.isVerified());
		
		if (val.isVerified()) {
			ElectionDto election = (ElectionDto) val.getObject();
			election.toString();
		}
	}

	@Test 
	public void testValidate() {
		ElectionDto election = new ElectionDto();
		
		election.setElectionName("automated election name");
		election.setElectionDescription("automated election description");
		election.setCandidatesListString("xxx\nxxx");
		election.setElectionType(ElectionType.PUBLIC.getCode());
		
		Validator val = election.Validate();
		assertTrue("validate election", val.isVerified());
		String testString = "";
		for (int i=0; i<129; i++) {
			testString += "a";
		}
		election.setElectionName(testString);
		
		testString = "";
		for (int i=0; i<1025; i++) {
			testString += "a";
		}
		election.setElectionDescription(testString);
		
		testString = "";
		for (int i=0; i<2049; i++) {
			testString += "a";
		}
		election.setCandidatesListString(testString);
		
		
		testString = "";
		for (int i=0; i<129; i++) {
			testString += "a";
		}
		election.setStartDatetime(testString);
		election.setCloseDatetime(testString);
		
		val = election.Validate();
		assertFalse("validate election failure", val.isVerified());
	}
	
	

	@Test
	public void testSelectElectionsOwnedByUser() {
		int ownerId = 1;
		Validator val = dbc.selectElectionsForOwner(ownerId);
		assertTrue("select elections owned by user ", val.isVerified());
	}

	@Test
	public void testSelectElectionsForAdmin() {
		Validator val = dbc.selectElectionsForAdmin();
		assertTrue("select all elections", val.isVerified());
	}

	@Test
	public void testSelectAllElectionsForVoter() {
		int userId = 1;
		Validator val = dbc.selectElectionsForVoter(userId);
		assertTrue("select elections owned by user", val.isVerified());
	}

	//@Test
	public void testAddPrivateElection() {
		// ElectionDto election = new ElectionDto();
		ElectionDto election = new ElectionDto();
		
		int ownerId = 1;
		
		election.setElectionName("automated test PRIVATE election name");
		election.setElectionDescription("automated test PRIVATE election description");
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
		
		election.setElectionType(ElectionType.PRIVATE.getCode());
		//election.setEmailList("hirosh@certus.org\ndummy@certus.org\nuser@certus.org\nmygoodness\nhirosh@yahoo.com\nthisisnotemail");
		election.setEmailList("hirosh@certus.org\ndummy@certus.org\nuser@certus.org\nhirosh@yahoo.com");
		System.out.println(election.toString());
		
		System.out.println("::::::::::::::::::::::::::::::::::::");
		
		Validator val = dbc.addElection(election);
		System.out.println("added ? : " + val.isVerified());
		System.out.println("add status : " + val.getStatus());
		
		ElectionDto electionAdd = (ElectionDto)val.getObject();
		System.out.println(electionAdd.toString());
		
		assertTrue("add election", val.isVerified());
		
	}
		
	//@Test
	public void testAddPublicElection() {
		// ElectionDto election = new ElectionDto();
		ElectionDto election = new ElectionDto();
		
		int ownerId = 1;
		
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
		//election.setEmailList("hirosh@certus.org\ndummy@certus.org\nuser@certus.org\nmygoodness\nhirosh@yahoo.com\nthisisnotemail");
		election.setEmailList("hirosh@certus.org\ndummy@certus.org\nuser@certus.org\nhirosh@yahoo.com");
		System.out.println(election.toString());
		
		
		Validator val = dbc.addElection(election);
		System.out.println("added ? : " + val.isVerified());
		System.out.println("add status : " + val.getStatus());
		
		ElectionDto electionAdd = (ElectionDto)val.getObject();
		System.out.println(electionAdd.toString());
		
		assertTrue("add election", val.isVerified());
	}
	

	@Test
	public void testEditPrivateElection() {
		int electionId = 16;
		int ownerId = 1;
		Validator val = dbc.selectElectionFullDetail(electionId);
		if (val.isVerified()){
			ElectionDto election = (ElectionDto) val.getObject();
			
			ElectionDto electionNew = new ElectionDto();
			electionNew.setElectionId(electionId);
			electionNew.setElectionName("automated election name");
			electionNew.setElectionDescription("automated election description");
			electionNew.setCandidatesListString("automated 1 \nautomated 2");
			electionNew.setOwnerId(ownerId); 
			electionNew.setElectionType(ElectionType.PRIVATE.getCode());
			electionNew.setEmailList("hirosh@certus.org\ndummy@certus.org\nuser@certus.org\nhirosh@yahoo.com");
			
			//electionNew.setStartDatetime();
			
			Validator valEdit = dbc.editElection(electionNew);
			System.out.println("edit election message : " + valEdit.getStatus());
			System.out.println("edit election status : " + valEdit.isVerified());
			assertTrue("edit election", valEdit.isVerified());
			
			//valEdit = dbc.editElection(election);
			//assertTrue("undo edit election", valEdit.isVerified());
			
		} else {
			assertFalse("select election failed", val.isVerified());
		}
	}

	
	@Test
	public void testVoteProgressStatusForElectionIntElectionId(){
		int electionId = 22;
		Validator val = dbc.voteProgressStatusForElection(electionId);
		assertTrue("vote progress", val.isVerified());
		
		if (val.isVerified()) {
			ElectionProgressDto progress = (ElectionProgressDto) val.getObject();
			System.out.println(progress.toString());
		}
	}
	
	@Test 
	public void testSelectResults() {
		int electionId = 13;
		Validator val = dbc.selectResults(electionId);
		assertTrue("elections results", val.isVerified());
		if (val.isVerified()) {
			ElectionDto results = (ElectionDto) val.getObject();
			System.out.println(results.toString());
			
			for(CandidateDto candidate: results.getCandidateList()) {
				System.out.println(candidate.toString());
			}
		}
	}
	
	@Test
	public void testOpenElectionAndPopulateCandidatesIntElectionId() {
		int electionId =74;
		Validator val = dbc.openElectionAndPopulateCandidates(electionId);
		
		if (val.isVerified()) {
			
			System.out.println("Open Election ::::::::::::::::::");
			System.out.println(val.getStatus());
			System.out.println(val.isVerified());
		}

		assertTrue("OpenElection", val.isVerified());
	}
	
	
	@Test
	public void testSelectElectionFullDetail() {
		int electionId = 54;
		Validator val = dbc.selectElectionFullDetail(electionId);
		if (val.isVerified()) {
			
			System.out.println("Opened Election ::::::::::::::::::");
			System.out.println(val.getStatus());
			System.out.println(((ElectionDto)val.getObject()).toString());
			
		}
		
		
		assertTrue("elections details with participating voters", val.isVerified());
	}
	
	//@Test
	public void testAddAdditionalUsersToElection() {
		int electionId = 70;
		ElectionDto electionDto = new ElectionDto();
		electionDto.setElectionId(electionId);
		String emailList = "user@somewhere.com\n";
		emailList += "sfrink1@gmail.com";
		//emailList += "bademal";
		electionDto.setEmailList(emailList);
		System.out.println("-----------------------------------------------------------");
		Validator val = dbc.addAdditionalUsersToElection(electionDto);
		System.out.println(val.getStatus());
		if (val.isVerified()) {
			
			System.out.println("Add aditional users");
			System.out.println(val.getStatus());
			System.out.println(((ElectionDto)val.getObject()).toString());
		}
		
		assertTrue("add additional voters ", val.isVerified());
	}
	
	//@Test
	public void testAddPrivateElectionWithInvitations() {
		ElectionDto electionDto = new ElectionDto();
		
		int ownerId = 1;
		electionDto.setOwnerId(ownerId);
		electionDto.setElectionName("Unit Testing");
		electionDto.setElectionDescription("Created by Unit testing");
		electionDto.setElectionType(ElectionType.PRIVATE.getCode());
		electionDto.setPassword("junit");
		electionDto.setCandidatesListString("choice A\nchoiceB\n");
		electionDto.setEmailList("hirosh@gwmail.gwu.edu\ndkarmazi@gwu.edu\n");
		electionDto.setEmailListInvited("sulochane@yahoo.com\nsulochane@gmail.com\n");
		
		Validator val = dbc.addElection(electionDto);
		assertTrue("add eleciton with invitations ", val.isVerified());
		
	}

	@Test
	public void testAddAdditionalUserInvitations(){
		ElectionDto electionDto = new ElectionDto();
		
		int electionId = 34;
		electionDto.setElectionId(electionId);
		electionDto.setEmailList("sulochane1@gmail.com");
		electionDto.setEmailListInvited("sulochane@gmail.com");
		Validator val = dbc.addAdditionalUsersToElection(electionDto);
		assertTrue("add additional users to election ", val.isVerified());
	}
}
