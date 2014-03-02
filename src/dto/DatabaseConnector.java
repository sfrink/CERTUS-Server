package dto;

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
	
	public Validator checkIfUsernamePasswordMatch(String email, String plainPass) {
		// 1. validate input
		Validator result = validateEmailAndPlainInput(email, plainPass);
		if (!result.isVerified()) {
			return result;
		}

		// 2. validate email
		result = verifyUserEmail(email);
		if (!result.isVerified()) {
			return result;
		}

		InputValidator iv = new InputValidator();
		PasswordHasher hasher = new PasswordHasher();

		// get this user limited info from the database
		UserDto userDto = selectUserByEmailLimited(email);

		String dbHash = userDto.getPassword();
		String dbSalt = userDto.getSalt();
		int statusId = userDto.getStatus();
		//int falseLogins = user.getFalseLogins();
		int id = userDto.getUser_id();

		// 3. check if this user is active
//		if (statusId != Enumeration.User.USER_STATUSID_ACTIVE) {
//			result.setVerified(false);
//			result.setStatus("Error, cannot login, this user account has been locked");
//			return result;
//		}

		String plainHash = hasher.sha512(plainPass, dbSalt);

		// 4. if entered password is correct, return true with welcome message
		if (plainHash.equals(dbHash)) {

			//updateDatabaseIntField("USERS", "ID", "FALSELOGINS", id, 0);
			//unsetActivationCodeAndTempPassword(id);
			result.setVerified(true);
			result.setStatus("Welcome to Certus");

			//LoggerCustom.logLoginActivity(email, "Login Successful");

			return result;
		} else {
			// 5. else record the failed login attempt
//			int newFalseLogins = falseLogins + 1;
//			updateDatabaseIntField("USERS", "ID", "FALSELOGINS", id,
//					newFalseLogins);
//
//			// if we reached the max of failed logins, lock the account, sent an
//			// email
//			if (newFalseLogins == Enumeration.User.USER_MAX_LOGIN_ATTEMPTS) {
//				// lock
//				updateDatabaseIntField("USERS", "ID", "STATUSID", id,
//						Enumeration.User.USER_STATUSID_LOCKED);
//
//				// generate activation code
//				String activationCode = setActivationCode(id);
//
//				// send email with activation code
//				SendEmail.sendEmailNotification(email,
//						Enumeration.Strings.ACCOUNT_LOCKED_SUBJECT,
//						Enumeration.Strings.ACCOUNT_LOCKED_MESSAGE
//								+ activationCode);
//
//				LoggerCustom.logLoginActivity(email, "Account locked");
//
//				result.setVerified(false);
//				result.setStatus("Error, exceeded the maximum number of login attempts, this user account has been locked");
//				return result;
//			} else {
//				result.setVerified(false);
//				result.setStatus("Error, the system could not resolve the provided combination of username and password.");
//				return result;
//			}
			
			result.setVerified(false);
			result.setStatus("Error, the system could not resolve the provided combination of username and password.");
			return result;
		}

	}
	
	public Validator validateEmailAndPlainInput(String email, String plainPass) {
		InputValidator iv = new InputValidator();
		Validator vResult = new Validator();
		Validator vEmail, vPlain;
		Boolean verified = true;
		String status = "";

		// 1. email
		vEmail = iv.validateEmail(email, "Email");
		verified &= vEmail.isVerified();
		status += vEmail.getStatus();

		// 2. plain
		vPlain = iv.validateString(plainPass, "Password");
		verified &= vPlain.isVerified();
		status += vPlain.getStatus();

		vResult.setVerified(verified);
		vResult.setStatus(status);

		return vResult;
	}
	
	public Validator verifyUserEmail(String emailToSelect) {
		Validator v = new Validator();
		v.setVerified(false);
		v.setStatus("Error, the system could not resolve the provided combination of username and password.");

		PreparedStatement st = null;
		String query = "SELECT user_id FROM users WHERE email = ?";

		try {
			st = con.prepareStatement(query);
			st.setString(1, emailToSelect);

			ResultSet res = st.executeQuery();

			if (res.next()) {
				v.setVerified(true);
				v.setStatus("");
				return v;
			}
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}

		return v;
	}

	public UserDto selectUserByEmailLimited(String emailToSelect) {
		UserDto userDto = new UserDto();

		PreparedStatement st = null;

		String query = "SELECT user_id, first_name, last_name, password, salt, status FROM users WHERE email = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setString(1, emailToSelect);

			ResultSet res = st.executeQuery();

			if (res.next()) {
				int user_id = res.getInt(1);
				String password = res.getString(4);
				String salt = res.getString(5);
				
				
				int statusId = res.getInt(6);
				
//				String salt = res.getString(2);
//				
//				int falseLogins = res.getInt(4);
//				int id = res.getInt(5);
//				int roleId = res.getInt(6);
//				String acticationCode = res.getString(7);
//				String activationCodeSalt = res.getString(8);
//				String tempPassword = res.getString(9);
//				String tempPasswordSalt = res.getString(10);
//				int firmId = res.getInt(11);

				userDto.setUser_id(user_id);
				userDto.setPassword(password);
				userDto.setSalt(salt);
				userDto.setStatus(statusId);
				
			} else {

			}

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}

		return userDto;
	}
}
	
	
	
	
	
