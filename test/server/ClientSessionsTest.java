package server;

import static org.junit.Assert.*;

import org.junit.Test;

import dto.UserDto;

public class ClientSessionsTest {

	@Test
	public void test() {
		ClientsSessions tester = new ClientsSessions();
		
		
		
		UserDto admin = new UserDto();
		UserDto user = new UserDto();
		
		admin.setUserId(1);
		admin.setType(1);
		
		user.setUserId(2);
		user.setType(0);
		
		String adminSession = tester.addNewClient(admin);
		String userSession = tester.addNewClient(user);
		
		assertTrue("isLoggedIn", tester.isLoggedIn(1));
		assertTrue("isLoggedIn", tester.isLoggedIn(userSession));
		
		assertEquals(adminSession, tester.getSession(1));
		assertEquals(2, tester.getSession(userSession));
		
		assertTrue("isAdmin", tester.isAdmin(1));
		assertTrue("isAdmin", tester.isAdmin(adminSession));
		
		assertTrue("isUser", tester.isUser(2));
		assertTrue("isUser", tester.isUser(userSession));
		
		
		assertTrue("removeUser", tester.removeClient(userSession));
	}

}
