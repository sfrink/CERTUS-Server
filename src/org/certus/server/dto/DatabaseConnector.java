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
		
	

	
	
	public UserDto selectUserById(int userId) {
		UserDto u = new UserDto();
		
		PreparedStatement st = null;
		String query = "SELECT * FROM users WHERE user_id = ?";
		
		try {
			st = con.prepareStatement(query);
			st.setInt(1, userId);
			ResultSet res = st.executeQuery();

			if (res.next()) {
				u.setUser_id(res.getInt(1));
				u.setFirst_name(res.getString(2));
				u.setLast_name(res.getString(3));
				u.setEmail(res.getString(4));
				u.setPassword(res.getString(5));
				u.setSalt(res.getString(6));
				u.setTemp_password(res.getString(7));
				u.setTemp_salt(res.getString(8));
				u.setActivation_code(res.getString(9));
				u.setPublic_key(res.getString(10));
				u.setAdministrator_flag(res.getInt(11));
				u.setStatus(res.getInt(12));				
			}
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		
		return u;
	}
	
	
}
	
	
	
	
	
