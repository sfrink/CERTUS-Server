package database;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

import dto.UserDto;
import dto.Validator;

public class advancedUserTesting {

	private DatabaseConnector dbc = new DatabaseConnector();
	
	@Test
	public void test() throws Exception {
		
		int userID = 0;
		String FirstName = "Automatic First name";
		String LastName = "Automatic Last name";
		String email = "adream_theater@hotmail.com";
		String userPassword = "UserPassword";
		String publicKeyPath = "F:\\temp\\public";
		
		BinFile publicKeyFile = new BinFile(publicKeyPath);
		
		byte[] publicKeyBytes = publicKeyFile.readFile();
		
		UserDto newUser = new UserDto();
		
		newUser.setFirstName(FirstName);
		newUser.setLastName(LastName);
		newUser.setEmail(email);
		newUser.setPassword(userPassword);
		
		Validator res = new Validator();
		
		res = dbc.addUser(newUser);
		
		assertTrue("addUser:" , res.isVerified());
		
		userID = (int) res.getObject();
		
		assertEquals(email, dbc.getUserEmail(userID));

		
	}

}
