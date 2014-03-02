package server;

import dto.*;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		DatabaseConnector db = new DatabaseConnector();
		
		UserDto u = db.selectUserById(1);
		
		System.out.println(u.toString());
		
		Validator v = db.checkIfUsernamePasswordMatch("jgalt@jg.com", "password");
		System.out.println(v.getStatus());
		
	}

}
