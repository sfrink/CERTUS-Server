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

public class Election
{
	private DatabaseConnector dbc = new DatabaseConnector();

	
	@Test
	public void testSelectElection() {
		//ElectionDto election = new ElectionDto();
		
		int electionId = 26;
		Validator val = dbc.selectElection(electionId);
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
		election.setCandidatesListString("automated 1 \nautomated 2");
		
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
		
		val = election.Validate();
		assertFalse("validate election failure", val.isVerified());
	}
	
	@Test
	public void testSelectElectionsByElectionStatus() {
		Validator val = dbc.selectElections(ElectionStatus.CLOSED);
		assertTrue("select elections by status (closed)", val.isVerified());
	}

	@Test
	public void testSelectElectionsNotInStatus() {
		Validator val = dbc.selectElections(ElectionStatus.DELETED);
		assertTrue("select elections not in status (deleted)", val.isVerified());
	}

	@Test
	public void testSelectElectionsOwnedByUserIntElectionStatus() {
		int ownerId = 1;
		Validator val = dbc.selectElectionsOwnedByUser(ownerId, ElectionStatus.NEW);
		assertTrue("select elections owned by user with status (new)", val.isVerified());
	}

	@Test
	public void testSelectElections() {
		Validator val = dbc.selectElections();
		assertTrue("select all elections", val.isVerified());
	}

	@Test
	public void testSelectElectionsOwnedByUserInt() {
		int ownerId = 1;
		Validator val = dbc.selectElectionsOwnedByUser(ownerId);
		assertTrue("select elections owned by user", val.isVerified());
	}

	@Test
	public void testSelectAllElectionsForVoter() {
		int userId = 1;
		Validator val = dbc.selectAllElectionsForVoter(userId);
		assertTrue("select elections owned by user", val.isVerified());
	}

	//@Test
	public void testAddElection() {
		// ElectionDto election = new ElectionDto();
		ElectionDto election = new ElectionDto();
		
		int ownerId = 1;
		
		election.setElectionName("automated election name");
		election.setElectionDescription("automated election description");
		election.setCandidatesListString("automated 1 \nautomated 2");
		election.setOwnerId(ownerId);
		Timestamp start = new Timestamp(System.currentTimeMillis());
		election.setStartDatetime(start);
		
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(start);
		calendar.add(Calendar.DAY_OF_WEEK, 7);
		Timestamp close = new Timestamp(calendar.getTimeInMillis());
		election.setCloseDatetime(close);
		
		//System.out.println(election.toString());
		
		Validator val = dbc.addElection(election);
		assertTrue("add election", val.isVerified());
		
		if (!val.isVerified()) {
			System.out.println("Add election failed :" );
			System.out.println(val.getStatus());
		}
		
		
	}
		
	

	@Test
	public void testEditElectionWithCandidatesString() {
		int electionId = 9;
		int ownerId = 1;
		Validator val = dbc.selectElection(electionId);
		if (val.isVerified()){
			ElectionDto election = (ElectionDto) val.getObject();
			
			ElectionDto electionNew = new ElectionDto();
			electionNew.setElectionId(electionId);
			electionNew.setElectionName("automated election name");
			electionNew.setElectionDescription("automated election description");
			electionNew.setCandidatesListString("automated 1 \nautomated 2");
			electionNew.setOwnerId(ownerId); 
			
			//electionNew.setStartDatetime();
			
			Validator valEdit = dbc.editElection(electionNew);
			assertTrue("edit election", valEdit.isVerified());
			
			valEdit = dbc.editElection(election);
			assertTrue("undo edit election", valEdit.isVerified());
			
		} else {
			assertFalse("select election failed", val.isVerified());
		}
	}

	@Test
	public void testEditElectionStatus() {
		int electionId = 11;

		Validator val = dbc.selectElection(electionId);
		if (val.isVerified()){
			ElectionDto election = (ElectionDto) val.getObject();

			Validator valEdit = dbc.editElectionStatus(electionId, ElectionStatus.getStatus(election.getStatus()));
			assertTrue("undo edit election status", valEdit.isVerified());
			
		} else {
			assertFalse("select election failed", val.isVerified());
		}
	}

	@Test
	public void testEditElection() {
		
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
		int electionId = 9;
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
	
}
