package server.dto;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.omg.CORBA.INITIALIZE;

import server.*;

public class DatabaseConnector {
	private static String dbHost;
	private static String dbPort;
	private static String dbUser;
	private static String dbPassword;
	private static String dbName;
	private Connection con;
	
	public DatabaseConnector() {
		Connection con = null;
		
		//System.out.println(ConfigurationProperties.dbHost());

		dbHost = ConfigurationProperties.dbHost();
		dbPort = ConfigurationProperties.dbPort();
		dbName = ConfigurationProperties.dbSchema();
		dbUser = ConfigurationProperties.dbUser();
		dbPassword = ConfigurationProperties.dbPassword();
		
		
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
	
	
	
	
	
