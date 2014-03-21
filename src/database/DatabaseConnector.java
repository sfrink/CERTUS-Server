package database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import server.ConfigurationProperties;
import server.InputValidator;
import server.PasswordHasher;
import dto.CandidateDto;
import dto.ElectionDto;
import dto.InputValidation;
import dto.UserDto;
import dto.Validator;
import dto.VoteDto;
import enumeration.Status;
import enumeration.ElectionStatus;

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
			System.out.println("Db connection failed");
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
			result.setObject(userDto);
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
				String first_name = res.getString(2);
				String last_name = res.getString(3);
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
				userDto.setFirst_name(first_name);
				userDto.setLast_name(last_name);
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
	
	// Election
	/**
	 * @param id(int) - Election identification number (primary key)
	 * @return ElectionDto - Details of a particular election
	 * @author Hirosh Wickramasuriya
	 */
	public ElectionDto selectElection(int id)
	{
		ElectionDto electionDto = new ElectionDto();
		
		PreparedStatement st = null;

		String query = "SELECT election_id, election_name, start_datetime, close_datetime, status, s.code, s.description, owner_id "
				+ " FROM election e "
				+ " INNER JOIN status_election s "
				+ " ON (e.status = s.status_id) "
				+ " WHERE election_id = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, id);

			ResultSet res = st.executeQuery();

			if (res.next()) {
				int election_id = res.getInt(1);
				String election_name = res.getString(2);
				Timestamp start_datetime = res.getTimestamp(3);
				Timestamp close_datetime = res.getTimestamp(4);
				int statusId = res.getInt(5);
				String statusCode = res.getString(6);
				String statusDescription = res.getString(7);
				int owner_id = res.getInt(8);

				electionDto.setElection_id(election_id);
				electionDto.setElection_name(election_name);
				electionDto.setStart_datetime(start_datetime);
				electionDto.setClose_datetime(close_datetime);
				electionDto.setStatus(statusId);
				electionDto.setStatusCode(statusCode);
				electionDto.setStatusDescription(statusDescription);
				electionDto.setOwner_id(owner_id);
				
			} else {

			}

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		return electionDto;
	}
	
	/**
	 * @param status(ElectionStatus) - specific status to be searched
	 * @return ArrayList<ElectionDto> - List of elections that matches a specific status
	 * @author Hirosh Wickramasuriya
	 */
	public ArrayList<ElectionDto> selectElections(ElectionStatus electionStatus)
	{
		ArrayList<ElectionDto> elections = new ArrayList<ElectionDto>();
		
		PreparedStatement st = null;

		String query = "SELECT election_id, election_name, start_datetime, close_datetime, status, s.code, s.description, owner_id"
				+ " FROM election e"
				+ " INNER JOIN status_election s "
				+ " ON (e.status = s.status_id) " 
				+ " WHERE status = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, electionStatus.getCode());

			ResultSet res = st.executeQuery();

			while (res.next()) {

				int election_id = res.getInt(1);
				String election_name = res.getString(2);
				Timestamp start_datetime = res.getTimestamp(3);
				Timestamp close_datetime = res.getTimestamp(4);
				int statusId = res.getInt(5);
				String statusCode = res.getString(6);
				String statusDescription = res.getString(7);
				int owner_id = res.getInt(8);
				
				ElectionDto electionDto = new ElectionDto();
				electionDto.setElection_id(election_id);
				electionDto.setElection_name(election_name);
				electionDto.setStart_datetime(start_datetime);
				electionDto.setClose_datetime(close_datetime);
				electionDto.setStatus(statusId);
				electionDto.setStatusCode(statusCode);
				electionDto.setStatusDescription(statusDescription);
				electionDto.setOwner_id(owner_id);
				
				elections.add(electionDto);
				
			} 

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		
		return elections;
		
	}
	
	/**
	 * @return ArrayList<ElectionDto>  - List of all the elections (regardless of status)
	 * @author Hirosh Wickramasuriya
	 */
	public ArrayList<ElectionDto> selectElections()
	{
		ArrayList<ElectionDto> elections = new ArrayList<ElectionDto>();
		
		PreparedStatement st = null;

		String query = "SELECT election_id, election_name, start_datetime, close_datetime, status, status, s.code, s.description, owner_id"
				+ " FROM election e"
				+ " INNER JOIN status_election s "
				+ " ON (e.status = s.status_id) " ;

		try {
			st = this.con.prepareStatement(query);

			ResultSet res = st.executeQuery();

			while (res.next()) {

				int election_id = res.getInt(1);
				String election_name = res.getString(2);
				Timestamp start_datetime = res.getTimestamp(3);
				Timestamp close_datetime = res.getTimestamp(4);
				int statusId = res.getInt(5);
				String statusCode = res.getString(6);
				String statusDescription = res.getString(7);
				int owner_id = res.getInt(8);
				
				ElectionDto electionDto = new ElectionDto();
				electionDto.setElection_id(election_id);
				electionDto.setElection_name(election_name);
				electionDto.setStart_datetime(start_datetime);
				electionDto.setClose_datetime(close_datetime);
				electionDto.setStatus(statusId);
				electionDto.setStatusCode(statusCode);
				electionDto.setStatusDescription(statusDescription);
				electionDto.setOwner_id(owner_id);
				
				elections.add(electionDto);
				
			} 

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		
		return elections;
		
	}
	
	// Candidates
	/**
	 * @param id - candidate identification number (primary key)
	 * @return CandidateDto - Details of a particular candidate
	 * @author Hirosh Wickramasuriya
	 */
	public CandidateDto selectCandidate(int id)
	{
		CandidateDto candidateDto = new CandidateDto();
		
		PreparedStatement st = null;

		String query = "SELECT candidate_id, candidate_name, election_id, display_order, status FROM candidate WHERE candidate_id = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, id);

			ResultSet res = st.executeQuery();

			if (res.next()) {
				
				int candidate_id = res.getInt(1);
				String candidate_name = res.getString(2);
				int election_id = res.getInt(3);
				int display_order = res.getInt(4);
				int statusId = res.getInt(5);

				candidateDto.setCandidate_id(candidate_id);
				candidateDto.setCandidate_name(candidate_name);
				candidateDto.setElection_id(election_id);
				candidateDto.setDisplay_order(display_order);
				candidateDto.setStatus(statusId);
				
			} else {

			}

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		return candidateDto;
	}
	
	/**
	 * @param election_id - election identification number
	 * @return ArrayList<CandidateDto> - list of all the candidates under specified election
	 * @author Hirosh Wickramasuriya
	 */
	public ArrayList<CandidateDto> selectCandidatesOfElection(int election_id)
	{
		ArrayList<CandidateDto> candidates = new ArrayList<CandidateDto>();
		
		PreparedStatement st = null;

		String query = "SELECT candidate_id, candidate_name, election_id, display_order, status FROM candidate WHERE election_id = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, election_id);

			ResultSet res = st.executeQuery();

			while (res.next()) {

				int candidate_id = res.getInt(1);
				String candidate_name = res.getString(2);
				int election_id_2 = res.getInt(3);
				int display_order = res.getInt(4);
				int statusId = res.getInt(5);

				CandidateDto candidateDto = new CandidateDto();
				candidateDto.setCandidate_id(candidate_id);
				candidateDto.setCandidate_name(candidate_name);
				candidateDto.setElection_id(election_id_2);
				candidateDto.setDisplay_order(display_order);
				candidateDto.setStatus(statusId);
				
				candidates.add(candidateDto);
				
			} 

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		
		return candidates;
	}
	
	/**
	 * @param election_id - election identification number
	 * @param candidateStatus - desired status of candidate which required to be returned for given election
	 * @return ArrayList<CandidateDto> - list of all the candidates that matches the status under specified election
	 * @author Hirosh Wickramasuriya
	 */
	public ArrayList<CandidateDto> selectCandidatesOfElection(int election_id, Status candidateStatus)
	{
		ArrayList<CandidateDto> candidates = new ArrayList<CandidateDto>();
		
		PreparedStatement st = null;

		String query = "SELECT candidate_id, candidate_name, election_id, display_order, status "
						+ "	FROM candidate "
						+ " WHERE election_id = ?"
						+ " AND status = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, election_id);
			st.setInt(2, candidateStatus.getCode());
			
			ResultSet res = st.executeQuery();

			while (res.next()) {

				int candidate_id = res.getInt(1);
				String candidate_name = res.getString(2);
				int election_id_2 = res.getInt(3);
				int display_order = res.getInt(4);
				int statusId = res.getInt(5);

				CandidateDto candidateDto = new CandidateDto();
				candidateDto.setCandidate_id(candidate_id);
				candidateDto.setCandidate_name(candidate_name);
				candidateDto.setElection_id(election_id_2);
				candidateDto.setDisplay_order(display_order);
				candidateDto.setStatus(statusId);
				
				candidates.add(candidateDto);
				
			} 

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		
		return candidates;
	}
	
	
	/**
	 * @param name - election name
	 * Add new election to db
	 * @author Steven Frink
	 */
	public void createNewElection(ElectionDto elec){
		PreparedStatement st=null;
		InputValidation iv=new InputValidation();
		Validator val=new Validator();
		
		try{
			val=iv.validateString(elec.getElection_name(), "Election name");
			if(val.isVerified()){
				String query = "INSERT INTO election (election_name, status, owner_id) VALUES (?,?,?)";
				int status=0;
				st=this.con.prepareStatement(query);
				st.setString(1, elec.getElection_name());
				st.setInt(2, status);
				st.setInt(3, elec.getOwner_id());
				st.execute();
			}
			else{
				System.out.println("Failed to validate");
			}
		}
		catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
	}
	
	/**
	 * @param names - candidate names
	 * @param election_id - the election to add candidates to
	 * Add candidates to an election
	 * @author Steven Frink
	 */
	public void addCandidatesToElection(ArrayList<CandidateDto> cands, int election_id){
		PreparedStatement st=null;
		InputValidation iv=new InputValidation();
		Validator val = new Validator();
		try{
			for(int i=0;i<cands.size();i++){
				val = iv.validateString(cands.get(i).getCandidate_name(), "Candidate Name");
				if(val.isVerified()){
					String query="INSERT INTO candidates (candidate_name, election_id, status) VALUES (?,?,?)";
					st=this.con.prepareStatement(query);
					st.setString(1,cands.get(i).getCandidate_name());
					st.setInt(2, election_id);
					st.setInt(3,1);
					st.execute();
				}
				else{
					System.out.println("Failed to validate");
				}
			}
		}
		catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
	}
	
	/**
	 * @param cand - candidate object
	 * @author Steven Frink
	 */
	public void editCandidate(CandidateDto cand){
		PreparedStatement st=null;
		InputValidation iv=new InputValidation();
		Validator val = new Validator();
		try{
			val = iv.validateString(cand.getCandidate_name(), "Candidate Name");
			boolean valid=true;
			valid&=val.isVerified();
			val=iv.validateInt(cand.getDisplay_order(), "Display Order");
			valid&=val.isVerified();
			if(valid){
				String query="UPDATE candidate SET (candidate_name, display_order)=(?,?) WHERE candidate_id=?";
				st=this.con.prepareStatement(query);
				st.setString(1, cand.getCandidate_name());
				st.setInt(2, cand.getDisplay_order());
				st.setInt(3,cand.getCandidate_id());
				st.execute();
			}
		}
		catch(SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		
	}
	
	/**
	 * @param election_id - the election to open
	 * Add candidates to an election
	 * @author Steven Frink
	 */
	public void openElection(int election_id){
		PreparedStatement st=null;
		try{
			String query="UPDATE election SET status=1 WHERE election_id="+election_id;
			st=this.con.prepareStatement(query);
			st.execute();
		}
		catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
	}
	
	/**
	 * @param election_id - the election to close
	 * Close an election
	 * @author Steven Frink
	 */
	public void closeElection(int election_id){
		PreparedStatement st=null;
		try{
			String query="UPDATE election SET status=8 WHERE election_id="+election_id;
			st=this.con.prepareStatement(query);
			st.execute();
		}
		catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
	}
	
	/**
	 * @param election_id - the election to delete
	 * Delete an election
	 * @author Steven Frink
	 */
	public void deleteElection(int election_id){
		PreparedStatement st=null;
		try{
			String query="UPDATE election SET status=7 WHERE election_id="+election_id;
			st=this.con.prepareStatement(query);
			st.execute();
		}
		catch(SQLException ex){
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
	}
	
	
	/**
	 * @param elec - the election to edit
	 * Edit an election
	 * @author Steven Frink
	 */
	public void editElection(ElectionDto elec){
		PreparedStatement st=null;
		InputValidation iv=new InputValidation();
		Validator val = new Validator();
		try{
			val = iv.validateString(elec.getElection_name(), "Election Name");
			if(val.isVerified()){
				String query="UPDATE election SET election_name=? WHERE election_id=?";
				st=this.con.prepareStatement(query);
				st.setString(1, elec.getElection_name());
				st.setInt(2,elec.getElection_id());
				st.execute();
			}
		}
		catch(SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
	}
	
	//Vote
	
	/**
	 * @param v - the vote to submit
	 * Submit a vote
	 * @author Steven Frink
	 */
	
	public void vote(VoteDto v){
		PreparedStatement st=null;
		InputValidation iv=new InputValidation();
		Validator val=new Validator();
		boolean valid=true;
		val=iv.validateInt(v.getUser_id(), "User ID");
		valid&=val.isVerified();
		val=iv.validateInt(v.getElection_id(), "Election ID");
		valid&=val.isVerified();
		val=iv.validateString(v.getVote_encrypted(), "Encrypted Vote");
		
		try{
			
			String query="INSERT INTO vote (user_id, election_id, vote_encrypted, vote_signature)"
					+ " VALUES (?,?,?,?)";
			st=this.con.prepareStatement(query);
			st.setInt(1, v.getUser_id());
			st.setInt(2, v.getElection_id());
			st.setString(3, v.getVote_encrypted());
			st.setString(4, v.getVote_signature());
			st.execute();
		}
		catch(SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
	}
}
