package server;

import server.dto.DatabaseConnector;
import server.dto.UserDto;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		DatabaseConnector db = new DatabaseConnector();
		
		UserDto u = db.selectUserById(1);
		
		System.out.println(u.toString());
		
	}

}
