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
		String keyPassword = "TempKeyPassword";
		String tempPassword = "TempPassword";
		String salt = "asdf";
		
		int action1 = 11;
		int action2 = 0;
		String method1 = "addUser";
		String method2 = "asdfasdf";
		
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
		newUser.setUserId(userID);

		res = dbc.getUserEmail(userID);
		
		assertTrue("getUserEmail:" , res.isVerified());

		res = dbc.generateNewKeys(userID, keyPassword, userPassword);
		
		assertTrue("generateNewKeys: ", res.isVerified());
		
		res = dbc.updateUser(newUser);
		
		assertTrue("updateUser", res.isVerified());
		
		res = dbc.setTempPassword(newUser, tempPassword, salt);
		
		assertTrue("setTempPassword", res.isVerified());
		
		newUser.setPublicKeyBytes(publicKeyBytes);
		newUser.setSalt(salt);
		
		res = dbc.updateTempUser(newUser);
		
		assertTrue("updateTempUser", res.isVerified());
		
		newUser.setTempPassword(tempPassword);
		
		res = dbc.UpdateTempUserWithPP(newUser);
		
		assertTrue("UpdateTempUserWithPP", res.isVerified());
		
		res = dbc.UpdateTempUserWithKey(newUser);
		
		assertTrue("UpdateTempUserWithKey", res.isVerified());	
		
		assertTrue("checkCorrectPassword", dbc.checkCorrectPassword(userID, userPassword));	
		
		newUser.setTempPassword(userPassword);
		
		res = dbc.updateUserPassword(newUser);
		
		assertTrue("updateUserPassword", res.isVerified());
		
		res = dbc.uploadPubKey(publicKeyBytes, userID, userPassword);
		
		assertTrue("uploadPubKey", res.isVerified());
		
		UserDto dbUser = dbc.selectUserById(userID);
		
		assertTrue("selectUserById", FirstName.equals(dbUser.getFirstName()));
		
		
		res = dbc.getUserRoleByID(userID);
		
		assertTrue("getUserRoleByID", res.isVerified());
		
		
		res = dbc.checkRoleRight(0, action1);
		
		assertTrue("checkRoleRight1", res.isVerified());
		
		res = dbc.checkRoleRight(1, action2);
		
		assertFalse("checkRoleRight2", res.isVerified());
		
		res = dbc.getActionIDbyMethod(method1);
		
		assertTrue("getActionIDbyMethod1", res.isVerified());
		
		res = dbc.getActionIDbyMethod(method2);
		
		assertFalse("getActionIDbyMethod2", res.isVerified());
		
		res = dbc.getRoleRights(1);
		
		assertTrue("getRoleRights", res.isVerified());
		
	}

	@Test
	public void test1() throws Exception {

		String FirstName = "Automatic First name";
		String LastName = "Automatic Last name";
		String email = "adream_theater1@hotmail.com";
		String userPassword = "UserPassword";
		String tempPassword = "TempPassword";
		
		UserDto newUser = new UserDto();
		
		newUser.setFirstName(FirstName);
		newUser.setLastName(LastName);
		newUser.setEmail(email);
		newUser.setPassword(userPassword);
		newUser.setTempPassword(tempPassword);
		
		Validator res = new Validator();
		
		res = dbc.addUserWithPP(newUser);
		
		assertTrue("addUserWithPP", res.isVerified());
	}
	
	@Test
	public void test2() throws Exception {
		int userID = 0;
		String FirstName = "Automatic First name";
		
		
		String LastName = "Automatic Last name";
		String email = "adream_theater2@hotmail.com";
		String userPassword = "UserPassword";
		String publicKeyPath = "F:\\temp\\public";

		
		BinFile publicKeyFile = new BinFile(publicKeyPath);
		
		byte[] publicKeyBytes = publicKeyFile.readFile();
		
		UserDto newUser = new UserDto();
		
		newUser.setFirstName(FirstName);
		newUser.setLastName(LastName);
		newUser.setEmail(email);
		newUser.setPassword(userPassword);
		newUser.setPublicKeyBytes(publicKeyBytes);
		
		Validator res = new Validator();
		
		res = dbc.addUserWithKey(newUser);
		
		assertTrue("addUserWithKey", res.isVerified());
	}
}
