package database;

import static org.junit.Assert.*;

import java.rmi.RemoteException;
import java.sql.Timestamp;
import java.util.Calendar;

import org.junit.Test;

import database.DatabaseConnector;
import dto.ElectionDto;
import dto.UserDto;
import dto.Validator;
import dto.VoteDto;
import enumeration.ElectionStatus;
import enumeration.ElectionType;
import rmi.CertusServer;

public class ElectionFullCycle
{

	private DatabaseConnector dbc = new DatabaseConnector();
	
	public ElectionFullCycle()
	{
		
	}
	
	
	//@Test
	public void testcheckIfUsernamePasswordMatch() throws RemoteException {
		Validator val = dbc.checkIfUsernamePasswordMatch("dkarmazi@gwu.edu", "password");
		if (!val.isVerified()) {
			System.out.println(val.toString());
			//xUserDto user = (UserDto)val.getObject();
			//sessionID1 = user.getSessionId();
		}
		assertTrue("select user", val.isVerified());
	}
	@Test
	public void testPublicElection() throws Exception{
		int newPublicElectionId = testAddPublicElection();
		testEditPublicElection(newPublicElectionId);
		testopenElectionAndPopulateCandidates(newPublicElectionId);	

		testgotAccessToPublicElection(newPublicElectionId);
		testCloseElection(newPublicElectionId);
		testReopenElection(newPublicElectionId);
		testVoteProgressStatusForElection(newPublicElectionId);
		testCloseElection(newPublicElectionId);
		testPublishElectionResults(newPublicElectionId);
		testGetPublishedElections();
		testGetElectionResults(newPublicElectionId);
		
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
		testVoteProgressStatusForElection(newPrivateElectionId);
		testCloseElection(newPrivateElectionId);
		testPublishElectionResults(newPrivateElectionId);
		testGetPublishedElections();
		testGetElectionResults(newPrivateElectionId);
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
		election.setEmailList("hirosh@gwmail.gwu.edu\ndkarmazi@gwu.edu\nsulochane@yahoo.com\n");
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
}
