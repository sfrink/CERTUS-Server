package database;

import static org.junit.Assert.*;

import org.junit.Test;

import dto.CandidateDto;
import dto.ElectionDto;
import dto.Validator;
import enumeration.ElectionStatus;
import enumeration.Status;

public class Candidate
{

	private DatabaseConnector dbc = new DatabaseConnector();
	
	@Test
	public void testSelectCandidate() {
		int candiateId = 5;
		Validator val = dbc.selectCandidate(candiateId);
		assertTrue("select candidate", val.isVerified());
		
		System.out.println("select candidate >");
		if (val.isVerified()) {
			CandidateDto candidate = (CandidateDto) val.getObject();
			System.out.println(candidate.toString());
		}
	}
	@Test 
	public void testValidate() {
		CandidateDto candidateDto = new CandidateDto();
		candidateDto.setCandidateName("test name");
		Validator val = candidateDto.Validate();
		System.out.println(val.toString());
		
		String testString = "";
		for (int i=0; i<129; i++) {
			testString += "a";
		}
		candidateDto.setCandidateName(testString);
		val = candidateDto.Validate();
		System.out.println(val.toString());
	}
	
	@Test
	public void testSelectCandidatesOfElectionInt() {
		int  electionIdKey = 17;
		Validator val = dbc.selectCandidatesOfElection(electionIdKey);
		assertTrue("select elections by status (closed)", val.isVerified());
	}

	@Test
	public void testSelectCandidatesOfElectionIntStatus() {
		int  electionIdKey = 17;
		Validator val = dbc.selectCandidatesOfElection(electionIdKey, Status.ENABLED);
		assertTrue("select elections by status (closed)", val.isVerified());
	}

	

}
