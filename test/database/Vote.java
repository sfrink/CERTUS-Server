package database;

import static org.junit.Assert.*;

import org.junit.Test;

import dto.ElectionProgressDto;
import dto.Validator;
import dto.VoteDto;

public class Vote
{
	private DatabaseConnector dbc = new DatabaseConnector();
	
	
	@Test
	public void testVote() {
		VoteDto vote = new VoteDto();
		vote.setUserId(1);
		vote.setElectionId(1);
		vote.setVoteEncrypted("invalid encrypted vote");
		vote.setVoteSignature("invalid signature for the vote");
		
		
		Validator val = dbc.vote(vote);
		assertFalse("invliad vote", val.isVerified());
	}

	@Test
	public void testVoteProgressStatusForElection() {
		int electionId = 22;
		Validator val = dbc.voteProgressStatusForElection(electionId);
		assertTrue("vote progress", val.isVerified());
		
		if (val.isVerified()) {
			ElectionProgressDto progress = (ElectionProgressDto) val.getObject();
			System.out.println(progress.toString());
		}
	}

}
