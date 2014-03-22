package server;

import java.util.Iterator;

import database.DatabaseConnector;
import dto.*;
import enumeration.ElectionStatus;

public class Main {

	public static void main(String[] args) {

		DatabaseConnector db = new DatabaseConnector();
		
		UserDto u = db.selectUserById(1);
		
		System.out.println(u.toString());
		
		Validator v = db.checkIfUsernamePasswordMatch("user@certus.org", "password");
		System.out.println(v.getStatus());
		
		// Retrieve Elections
		ElectionDto electionDto = db.selectElection(1);
		System.out.println(electionDto.toString());
		
		for (ElectionDto e : db.selectElections(ElectionStatus.NEW)) {
			System.out.println(e.toString());
		}

		// Retrieve Candidates
		CandidateDto candidateDto = db.selectCandidate(1);
		System.out.println(candidateDto.toString());
		
		for (CandidateDto c : db.selectCandidatesOfElection(1)) {
			System.out.println(c.toString());
		}
	}

}
