package org.certus.server.dto;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;


public class DatabaseConnector {
	private static String dbHost = "128.164.159.149";
	private static String dbPort = "3306";
	private static String dbUser = "repo6908";
	private static String dbPassword = "arWqs1931_6908";
	private static String dbName = "repo6908";
	private Connection con;

	
	public DatabaseConnector() {
		Connection con = null;
		try {
			Class.forName("com.mysql.jdbc.Driver");
			String url = "jdbc:mysql://" + dbHost + ":" + dbPort + "/" + dbName;
			con = DriverManager.getConnection(url, dbUser,
					dbPassword);
			this.con = con;
		} catch (Exception e) {
			e.printStackTrace();
		}

		
	}
		
	

	
	
	public void selectUserById(int userId) {
		PreparedStatement st = null;
		String query = "SELECT count(user_id) FROM users";
		
		try {
			st = con.prepareStatement(query);
			ResultSet res = st.executeQuery();

			if (res.next()) {
				System.out.println("DB query worked");
			}
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
	}
	
	
}
	
	
	
	
	
