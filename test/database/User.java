package database;

import static org.junit.Assert.*;

import java.util.ArrayList;

import org.junit.Test;

import dto.UserDto;
import dto.Validator;
import enumeration.UserStatus;

public class User
{

	private DatabaseConnector dbc = new DatabaseConnector();
	
	@Test
	public void testAddUser() {
		//fail("Not yet implemented");
		
		UserDto user  =  new UserDto();
		
		user.setFirstName("Test First");
		user.setLastName("Test Last");
		user.setEmail("user@somewhere.com");
		
		
		//Validator vAddUser = dbc.addUser(user);
		
		
		//assertTrue("add user pass", vAddUser.isVerified());
		
		
	}
	
	@Test
	public void testValidate(){
		UserDto userDto = new UserDto();
		userDto.setFirstName("firstName");
		userDto.setLastName("lastName");
		userDto.setEmail("test@yahoo.com");
		
		Validator val = userDto.Validate();
		assertTrue("validate valid user details", val.isVerified());
		
		String testString = "";
		for (int i=0; i<257; i++) {
			testString += "a";
		}
		userDto.setFirstName(testString);
		
		testString = "";
		for (int i=0; i<257; i++) {
			testString += "a";
		}
		userDto.setLastName("");
		
		userDto.setEmail("invalid@com");
		val = userDto.Validate();
		assertFalse("validate invalid user details", val.isVerified());
	}
	
	@Test
	public void editUser() {
		//fail("Not yet implemented");
		
		UserDto user  =  new UserDto();
		user.setUserId(5);
		user.setFirstName("Test First modified");
		user.setLastName("Test Last modified");
		user.setEmail("user_modified@somewhere.com");
		user.setStatus(2);
		
		Validator vEditUser = dbc.editUser(user);
		assertTrue("edit user", vEditUser.isVerified());
		
	}
	
	@Test
	public void selectAllUsers() {
		Validator val = dbc.selectAllUsers();
		assertTrue("select users", val.isVerified());
		ArrayList<UserDto> users = new ArrayList<UserDto>();
		users = (ArrayList<UserDto> )val.getObject();
		for (UserDto u : users) {
			System.out.println(u.toString());
		}
	}
	
	@Test
	public void editStatus() {
		Validator val = dbc.editUserStatus(4, UserStatus.LOCKED);
		assertTrue("select users", val.isVerified());
	
	}
	
	@Test
	public void selectUser() {
		Validator val = dbc.selectUser(4);
		assertTrue("select user", val.isVerified());

		UserDto user = (UserDto)val.getObject();
		
		assertTrue("selected user - first name ", ( user.getFirstName().equals("Test First")) );
		assertTrue("selected user - last name ", user.getLastName().equals("Test Last") );
		assertTrue("selected user - email ", user.getEmail().equals("user@somewhere.com") );
		assertTrue("selected user - status ", user.getStatus() == 2);
	}
	
}
