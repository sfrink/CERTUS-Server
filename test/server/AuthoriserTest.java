package server;

import static org.junit.Assert.*;

import org.junit.Test;

import database.DatabaseConnector;
import dto.Validator;

public class AuthoriserTest {
	
	private DatabaseConnector dbc = new DatabaseConnector();
	
	@Test
	public void test() {
		Authoriser tester = new Authoriser(dbc);
		
		Validator res = new Validator();
		
		res = tester.getAllRoleRights(1);
		
		assertTrue("getAllRoleRights", res.isVerified());
		
		res = tester.getAllUserRights(1);
		
		assertTrue("getAllUserRights", res.isVerified());
		
		assertFalse("isAllowedToVote", tester.isAllowedToVote(1, 2, 3, "vote"));
	
		assertFalse("isAllowedToViewResults", tester.isAllowedToViewResults(1, 2, "selectResults"));
		
		assertTrue("gotRightsGroup0", tester.gotRightsGroup0(1, "selectUser"));

	}

}
