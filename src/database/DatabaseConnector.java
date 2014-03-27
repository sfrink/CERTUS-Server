package database;

import java.security.acl.Owner;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import server.ConfigurationProperties;
import server.InputValidator;
import server.PasswordHasher;
import server.SecurityValidator;
import dto.CandidateDto;
import dto.ElectionDto;
import dto.ElectionProgressDto;
import dto.InputValidation;
import dto.UserDto;
import dto.Validator;
import dto.VoteDto;
import enumeration.Status;
import enumeration.ElectionStatus;

/**
 * @author sulo
 * 
 */
public class DatabaseConnector
{
	private static String	dbHost;
	private static String	dbPort;
	private static String	dbUser;
	private static String	dbPassword;
	private static String	dbName;
	private Connection		con;

	public DatabaseConnector()
	{
		Connection con = null;

		// System.out.println(ConfigurationProperties.dbHost());

		dbHost = ConfigurationProperties.dbHost();
		dbPort = ConfigurationProperties.dbPort();
		dbName = ConfigurationProperties.dbSchema();
		dbUser = ConfigurationProperties.dbUser();
		dbPassword = ConfigurationProperties.dbPassword();

		try {
			Class.forName("com.mysql.jdbc.Driver");
			String url = "jdbc:mysql://" + dbHost + ":" + dbPort + "/" + dbName;
			con = DriverManager.getConnection(url, dbUser, dbPassword);
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
				u.setUserId(res.getInt(1));
				u.setFirstName(res.getString(2));
				u.setLastName(res.getString(3));
				u.setEmail(res.getString(4));
				u.setPassword(res.getString(5));
				u.setSalt(res.getString(6));
				u.setTempPassword(res.getString(7));
				u.setTempSalt(res.getString(8));
				u.setActivationCode(res.getString(9));
				u.setPublicKey(res.getString(10));
				u.setAdministratorFlag(res.getInt(11));
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
		// int falseLogins = user.getFalseLogins();
		int id = userDto.getUserId();

		// 3. check if this user is active
		// if (statusId != Enumeration.User.USER_STATUSID_ACTIVE) {
		// result.setVerified(false);
		// result.setStatus("Error, cannot login, this user account has been locked");
		// return result;
		// }

		String plainHash = hasher.sha512(plainPass, dbSalt);

		// 4. if entered password is correct, return true with welcome message
		if (plainHash.equals(dbHash)) {

			// updateDatabaseIntField("USERS", "ID", "FALSELOGINS", id, 0);
			// unsetActivationCodeAndTempPassword(id);
			result.setObject(userDto);
			result.setVerified(true);
			result.setStatus("Welcome to Certus");

			// LoggerCustom.logLoginActivity(email, "Login Successful");

			return result;
		} else {
			// 5. else record the failed login attempt
			// int newFalseLogins = falseLogins + 1;
			// updateDatabaseIntField("USERS", "ID", "FALSELOGINS", id,
			// newFalseLogins);
			//
			// // if we reached the max of failed logins, lock the account, sent
			// an
			// // email
			// if (newFalseLogins == Enumeration.User.USER_MAX_LOGIN_ATTEMPTS) {
			// // lock
			// updateDatabaseIntField("USERS", "ID", "STATUSID", id,
			// Enumeration.User.USER_STATUSID_LOCKED);
			//
			// // generate activation code
			// String activationCode = setActivationCode(id);
			//
			// // send email with activation code
			// SendEmail.sendEmailNotification(email,
			// Enumeration.Strings.ACCOUNT_LOCKED_SUBJECT,
			// Enumeration.Strings.ACCOUNT_LOCKED_MESSAGE
			// + activationCode);
			//
			// LoggerCustom.logLoginActivity(email, "Account locked");
			//
			// result.setVerified(false);
			// result.setStatus("Error, exceeded the maximum number of login attempts, this user account has been locked");
			// return result;
			// } else {
			// result.setVerified(false);
			// result.setStatus("Error, the system could not resolve the provided combination of username and password.");
			// return result;
			// }

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

				// String salt = res.getString(2);
				//
				// int falseLogins = res.getInt(4);
				// int id = res.getInt(5);
				// int roleId = res.getInt(6);
				// String acticationCode = res.getString(7);
				// String activationCodeSalt = res.getString(8);
				// String tempPassword = res.getString(9);
				// String tempPasswordSalt = res.getString(10);
				// int firmId = res.getInt(11);

				userDto.setUserId(user_id);
				userDto.setFirstName(first_name);
				userDto.setLastName(last_name);
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
	 * @param id
	 *            (int) - Election identification number (primary key)
	 * @return Validator : ElectionDto - Details of a particular election
	 * @author Hirosh Wickramasuriya
	 */
	public Validator selectElection(int id) {
		Validator validator = new Validator();
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
				int electionId = res.getInt(1);
				String electionName = res.getString(2);
				Timestamp startDatetime = res.getTimestamp(3);
				Timestamp closeDatetime = res.getTimestamp(4);
				int statusId = res.getInt(5);
				String statusCode = res.getString(6);
				String statusDescription = res.getString(7);
				int ownerId = res.getInt(8);

				electionDto.setElectionId(electionId);
				electionDto.setElectionName(electionName);
				electionDto.setStartDatetime(startDatetime);
				electionDto.setCloseDatetime(closeDatetime);
				electionDto.setStatus(statusId);
				electionDto.setStatusCode(statusCode);
				electionDto.setStatusDescription(statusDescription);
				electionDto.setOwnerId(ownerId);

				Validator vCandidates = selectCandidatesOfElection(electionId);
				electionDto.setCandidateList( (ArrayList<CandidateDto>) vCandidates.getObject());
			}
			validator.setVerified(true);
			validator.setObject(electionDto);
			validator.setStatus("Select successful");

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			validator.setVerified(false);
			validator.setStatus("Select failed");
		}

		return validator;
	}

	/**
	 * @param status
	 *            (ElectionStatus) - specific status to be searched
	 * @return Validator : ArrayList<ElectionDto> - List of elections that
	 *         matches a specific status
	 * @author Hirosh Wickramasuriya
	 */
	public Validator selectElections(ElectionStatus electionStatus) {
		Validator validator = new Validator();
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

				int electionId = res.getInt(1);
				String electionName = res.getString(2);
				Timestamp startDatetime = res.getTimestamp(3);
				Timestamp closeDatetime = res.getTimestamp(4);
				int statusId = res.getInt(5);
				String statusCode = res.getString(6);
				String statusDescription = res.getString(7);
				int ownerId = res.getInt(8);

				ElectionDto electionDto = new ElectionDto();
				electionDto.setElectionId(electionId);
				electionDto.setElectionName(electionName);
				electionDto.setStartDatetime(startDatetime);
				electionDto.setCloseDatetime(closeDatetime);
				electionDto.setStatus(statusId);
				electionDto.setStatusCode(statusCode);
				electionDto.setStatusDescription(statusDescription);
				electionDto.setOwnerId(ownerId);

				elections.add(electionDto);
			}
			validator.setVerified(true);
			validator.setObject(elections);
			validator.setStatus("Successfully selected");

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			validator.setStatus("Select Failed.");
		}

		return validator;

	}

	/**
	 * @param electionOwnerId
	 *            (int) - user_id of the user who owns this election
	 * @param status
	 *            (ElectionStatus) - specific status to be searched
	 * @return Validator : ArrayList<ElectionDto> - List of elections owned by
	 *         the specific user, that matches a specific status
	 * @author Hirosh Wickramasuriya
	 */
	public Validator selectElectionsOwnedByUser(int electionOwnerId, ElectionStatus electionStatus) {
		Validator validator = new Validator();
		ArrayList<ElectionDto> elections = new ArrayList<ElectionDto>();

		PreparedStatement st = null;

		String query = "SELECT election_id, election_name, start_datetime, close_datetime, status, s.code, s.description, owner_id"
				+ " FROM election e"
				+ " INNER JOIN status_election s "
				+ " ON (e.status = s.status_id) "
				+ " WHERE owner_id = ?" + " AND status = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, electionOwnerId);
			st.setInt(2, electionStatus.getCode());

			ResultSet res = st.executeQuery();

			while (res.next()) {

				int electionId = res.getInt(1);
				String electionName = res.getString(2);
				Timestamp startDatetime = res.getTimestamp(3);
				Timestamp closeDatetime = res.getTimestamp(4);
				int statusId = res.getInt(5);
				String statusCode = res.getString(6);
				String statusDescription = res.getString(7);
				int ownerId = res.getInt(8);

				ElectionDto electionDto = new ElectionDto();
				electionDto.setElectionId(electionId);
				electionDto.setElectionName(electionName);
				electionDto.setStartDatetime(startDatetime);
				electionDto.setCloseDatetime(closeDatetime);
				electionDto.setStatus(statusId);
				electionDto.setStatusCode(statusCode);
				electionDto.setStatusDescription(statusDescription);
				electionDto.setOwnerId(ownerId);

				elections.add(electionDto);
			}
			validator.setVerified(true);
			validator.setObject(elections);
			validator.setStatus("Successfully selected");

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			validator.setStatus("Select failed");
		}

		return validator;

	}

	/**
	 * @return Validator : ArrayList<ElectionDto> - List of all the elections
	 *         (regardless of status)
	 * @author Hirosh Wickramasuriya
	 */
	public Validator selectElections() {
		Validator validator = new Validator();
		ArrayList<ElectionDto> elections = new ArrayList<ElectionDto>();

		PreparedStatement st = null;

		String query = "SELECT election_id, election_name, start_datetime, close_datetime, status, s.code, s.description, owner_id"
				+ " FROM election e" + " INNER JOIN status_election s " + " ON (e.status = s.status_id) ";

		try {
			st = this.con.prepareStatement(query);

			ResultSet res = st.executeQuery();

			while (res.next()) {

				int electionId = res.getInt(1);
				String electionName = res.getString(2);
				Timestamp startDatetime = res.getTimestamp(3);
				Timestamp closeDatetime = res.getTimestamp(4);
				int statusId = res.getInt(5);
				String statusCode = res.getString(6);
				String statusDescription = res.getString(7);
				int ownerId = res.getInt(8);

				ElectionDto electionDto = new ElectionDto();
				electionDto.setElectionId(electionId);
				electionDto.setElectionName(electionName);
				electionDto.setStartDatetime(startDatetime);
				electionDto.setCloseDatetime(closeDatetime);
				electionDto.setStatus(statusId);
				electionDto.setStatusCode(statusCode);
				electionDto.setStatusDescription(statusDescription);
				electionDto.setOwnerId(ownerId);

				elections.add(electionDto);
			}
			validator.setVerified(true);
			validator.setObject(elections);
			validator.setStatus("Successfully selected");

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			validator.setStatus("Select failed");
		}

		return validator;

	}

	/**
	 * @param election_owner_id
	 *            (int) - user_id of the user who owns elections
	 * @return Validator : ArrayList<ElectionDto> - List of all the elections
	 *         owned by the specific user (regardless of status)
	 * @author Hirosh Wickramasuriya
	 */
	public Validator selectElectionsOwnedByUser(int electionOwnerId) {
		Validator validator = new Validator();
		ArrayList<ElectionDto> elections = new ArrayList<ElectionDto>();

		PreparedStatement st = null;

		String query = "SELECT election_id, election_name, start_datetime, close_datetime, status, s.code, s.description, owner_id"
				+ " FROM election e"
				+ " INNER JOIN status_election s "
				+ " ON (e.status = s.status_id) "
				+ " WHERE owner_id = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, electionOwnerId);

			ResultSet res = st.executeQuery();

			while (res.next()) {

				int electionId = res.getInt(1);
				String electionName = res.getString(2);
				Timestamp startDatetime = res.getTimestamp(3);
				Timestamp closeDatetime = res.getTimestamp(4);
				int statusId = res.getInt(5);
				String statusCode = res.getString(6);
				String statusDescription = res.getString(7);
				int ownerId = res.getInt(8);

				ElectionDto electionDto = new ElectionDto();
				electionDto.setElectionId(electionId);
				electionDto.setElectionName(electionName);
				electionDto.setStartDatetime(startDatetime);
				electionDto.setCloseDatetime(closeDatetime);
				electionDto.setStatus(statusId);
				electionDto.setStatusCode(statusCode);
				electionDto.setStatusDescription(statusDescription);
				electionDto.setOwnerId(ownerId);

				elections.add(electionDto);
			}
			validator.setVerified(true);
			validator.setObject(elections);
			validator.setStatus("Successfully selected");

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			validator.setStatus("Select failed");
		}

		return validator;

	}

	public Validator selectAllElectionsForVoter(int user_id) {
		Validator val = new Validator();
		ArrayList<ElectionDto> elecs = new ArrayList<ElectionDto>();
		PreparedStatement st = null;

		String query = "SELECT e.election_id, e.election_name, e.owner_id, "
				+ "e.start_datetime, e.close_datetime FROM election as e "
				+ "LEFT JOIN vote as v ON e.election_id = v.election_id "
				+ "WHERE v.user_id is null  OR v.user_id != ? AND e.status = ? "
				+ "GROUP BY e.election_id";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, user_id);
			st.setInt(2, ElectionStatus.OPEN.getCode());
			ResultSet res = st.executeQuery();

			while (res.next()) {
				ElectionDto e = new ElectionDto();
				e.setElectionId(res.getInt(1));
				e.setCandidateList((ArrayList<CandidateDto>) selectCandidatesOfElection(
						e.getElectionId()).getObject());
				e.setElectionName(res.getString(2));
				e.setOwnerId(res.getInt(3));
				e.setStartDatetime(res.getTimestamp(4));
				e.setCloseDatetime(res.getTimestamp(5));
				elecs.add(e);
			}
			val.setStatus("Retrieved Elections");
			val.setVerified(true);
			val.setObject(elecs);
			return val;
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			val.setStatus("Select failed");
			val.setVerified(false);
			return val;
		}
	}

	// Candidates
	/**
	 * @param id
	 *            - candidate identification number (primary key)
	 * @return Validator :CandidateDto - Details of a particular candidate
	 * @author Hirosh Wickramasuriya
	 */
	public Validator selectCandidate(int id) {
		Validator validator = new Validator();
		CandidateDto candidateDto = new CandidateDto();

		PreparedStatement st = null;

		String query = "SELECT candidate_id, candidate_name, election_id, display_order, status FROM candidate WHERE candidate_id = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, id);

			ResultSet res = st.executeQuery();

			if (res.next()) {

				int candidateId = res.getInt(1);
				String candidate_name = res.getString(2);
				int electionId = res.getInt(3);
				int displayOrder = res.getInt(4);
				int statusId = res.getInt(5);

				candidateDto.setCandidateId(candidateId);
				candidateDto.setCandidateName(candidate_name);
				candidateDto.setElectionId(electionId);
				candidateDto.setDisplayOrder(displayOrder);
				candidateDto.setStatus(statusId);

				validator.setVerified(true);
				validator.setObject(candidateDto);
				validator.setStatus("Successfully selected");
			}

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			validator.setStatus("Select failed");
		}

		return validator;
	}

	/**
	 * @param electionIdKey
	 *            - election identification number
	 * @return Validator : ArrayList<CandidateDto>- list of all the candidates
	 *         under specified election
	 * @author Hirosh Wickramasuriya
	 */
	public Validator selectCandidatesOfElection(int electionIdKey) {
		Validator validator = new Validator();
		ArrayList<CandidateDto> candidates = new ArrayList<CandidateDto>();

		PreparedStatement st = null;

		String query = "SELECT candidate_id, candidate_name, election_id, display_order, status FROM candidate WHERE election_id = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, electionIdKey);

			ResultSet res = st.executeQuery();

			while (res.next()) {

				int candidateId = res.getInt(1);
				String candidateName = res.getString(2);
				int electionId = res.getInt(3);
				int displayOrder = res.getInt(4);
				int statusId = res.getInt(5);

				CandidateDto candidateDto = new CandidateDto();
				candidateDto.setCandidateId(candidateId);
				candidateDto.setCandidateName(candidateName);
				candidateDto.setElectionId(electionId);
				candidateDto.setDisplayOrder(displayOrder);
				candidateDto.setStatus(statusId);

				candidates.add(candidateDto);
			}
			validator.setVerified(true);
			validator.setObject(candidates);
			validator.setStatus("Successfully selected");

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			validator.setStatus("select failed");
		}

		return validator;
	}

	/**
	 * @param electionIdKey
	 *            - election identification number
	 * @param candidateStatus
	 *            - desired status of candidate which required to be returned
	 *            for given election
	 * @return Validator :ArrayList<CandidateDto> - list of all the candidates
	 *         that matches the status under specified election
	 * @author Hirosh Wickramasuriya
	 */
	public Validator selectCandidatesOfElection(int electionIdKey, Status candidateStatus) {
		Validator validator = new Validator();
		ArrayList<CandidateDto> candidates = new ArrayList<CandidateDto>();

		PreparedStatement st = null;

		String query = "SELECT candidate_id, candidate_name, election_id, display_order, status " + "	FROM candidate "
				+ " WHERE election_id = ?" + " AND status = ?";

		try {
			st = this.con.prepareStatement(query);
			st.setInt(1, electionIdKey);
			st.setInt(2, candidateStatus.getCode());

			ResultSet res = st.executeQuery();

			while (res.next()) {

				int candidateId = res.getInt(1);
				String candidateName = res.getString(2);
				int electionId = res.getInt(3);
				int displayOrder = res.getInt(4);
				int statusId = res.getInt(5);

				CandidateDto candidateDto = new CandidateDto();
				candidateDto.setCandidateId(candidateId);
				candidateDto.setCandidateName(candidateName);
				candidateDto.setElectionId(electionId);
				candidateDto.setDisplayOrder(displayOrder);
				candidateDto.setStatus(statusId);

				candidates.add(candidateDto);
			}
			validator.setVerified(true);
			validator.setObject(candidates);
			validator.setStatus("Successfully selected");

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			validator.setVerified(false);
			validator.setStatus("Select failed");
		}
		return validator;
	}

	/**
	 * @param name
	 *            - election name Add new election to db
	 * @author Steven Frink
	 */
	private int addElection(ElectionDto electionDto) {
		PreparedStatement st = null;
		ResultSet rs = null;
		int newId = 0;

		try {
			String query = "INSERT INTO election (election_name, status, owner_id) VALUES (?,?,?)";
			int status = ElectionStatus.NEW.getCode();
			st = this.con.prepareStatement(query, Statement.RETURN_GENERATED_KEYS);
			st.setString(1, electionDto.getElectionName());
			st.setInt(2, status);
			st.setInt(3, electionDto.getOwnerId());

			// update query
			st.executeUpdate();
			// get inserted id
			rs = st.getGeneratedKeys();
			rs.next();
			newId = rs.getInt(1);

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}

		return newId;
	}

	/**
	 * @param name
	 *            - election name Add new election to db
	 * @author Steven Frink
	 */
	public Validator addElectionWithCandidates(ElectionDto electionDto) {

		Validator out = new Validator();
		// Validate the election
		Validator vElection = electionDto.Validate();
		Validator vCandidates = new Validator();

		if (vElection.isVerified()) {
			// insert election
			int electionId = addElection(electionDto);

			if (electionId > 0) {
				// if insert of elections was successful, insert candidate list
				vCandidates = addCandidatesToElection(electionDto.getCandidateList(), electionId);

				if (vCandidates.isVerified()) {
					// if candidates insert was successful
					ArrayList<CandidateDto> candidates = (ArrayList<CandidateDto>) vCandidates.getObject();
					electionDto.setElectionId(electionId);
					electionDto.setCandidateList(candidates);

					out.setVerified(true);
					out.setStatus("Election has been successfully inserted");
					out.setObject(electionDto);
				} else {
					out.setVerified(false);
					out.setStatus("Candidates insert failed");
				}
			} else {
				out.setVerified(false);
				out.setStatus("Election insert failed");
			}
		} else {
			out.setVerified(false);
			out.setStatus(vElection.getStatus());
		}

		return out;
	}

	/**
	 * @param candidateList
	 *            - candidate array list
	 * @param election_id
	 *            - the election to add candidates to Add candidates to an
	 *            election
	 * @author Steven Frink
	 */
	private Validator addCandidatesToElection(ArrayList<CandidateDto> candidateList, int election_id) {
		PreparedStatement st = null;
		ResultSet rs = null;
		Validator val = new Validator();
		int newCandidateId = 0;

		try {

			for (int i = 0; i < candidateList.size(); i++) {
				String query = "INSERT INTO candidate (candidate_name, election_id, status) VALUES (?,?,?)";
				st = this.con.prepareStatement(query, Statement.RETURN_GENERATED_KEYS);
				st.setString(1, candidateList.get(i).getCandidateName());
				st.setInt(2, election_id);
				st.setInt(3, Status.ENABLED.getCode());

				// run the query and get new candidate id
				st.executeUpdate();
				rs = st.getGeneratedKeys();
				rs.next();
				newCandidateId = rs.getInt(1);
				candidateList.get(i).setCandidateId(newCandidateId);
			}

			val.setVerified(true);
			val.setStatus("Candidates inserted successfully");
			val.setObject(candidateList);

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			val.setVerified(false);
			val.setStatus("SQL Error");
		}

		return val;
	}

	/**
	 * @param candidateDto
	 *            - candidate object
	 * @param election_id
	 *            - id of the election which the candidate should be associated
	 * @return Validator - status of the candidate insert operation
	 * @author Hirosh Wickramasuriya
	 */
	private Validator addCandidateToElection(CandidateDto candidateDto, int election_id) {
		PreparedStatement st = null;
		ResultSet rs = null;
		Validator val = new Validator();
		int newCandidateId = 0;

		try {

			String query = "INSERT INTO candidate (candidate_name, election_id, status) VALUES (?,?,?)";
			st = this.con.prepareStatement(query, Statement.RETURN_GENERATED_KEYS);
			st.setString(1, candidateDto.getCandidateName());
			st.setInt(2, election_id);
			st.setInt(3, Status.ENABLED.getCode());

			// run the query and get new candidate id
			st.executeUpdate();
			rs = st.getGeneratedKeys();
			rs.next();
			newCandidateId = rs.getInt(1);
			if (newCandidateId > 0) {
				candidateDto.setCandidateId(newCandidateId);
				val.setVerified(true);
				val.setStatus("Candidates inserted successfully");
				val.setObject(candidateDto);
			} else {
				val.setStatus("Failed to insert candidate");
			}

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			val.setVerified(false);
			val.setStatus("SQL Error");
		}

		return val;
	}

	/**
	 * @param electionDto
	 *            - election data object
	 * @return validator - status of election update operation
	 * @author Hirosh / Dmitry
	 */
	public Validator editElectionWithCandidates(ElectionDto electionDto) {

		Validator out = new Validator();

		String delimiter = "\n";

		// 0. check the election status.
		ElectionDto vElectionCurrent = (ElectionDto) selectElection(electionDto.getElectionId()).getObject();
		if (vElectionCurrent.getStatus() == ElectionStatus.NEW.getCode())
		{
			// 1. Validate e
			Validator vElection = electionDto.Validate();
			if (vElection.isVerified()) {
				// 2. Update the election details
				Validator vElectionUpdated = editElection(electionDto);

				if (vElectionUpdated.isVerified()) {
					// election updated, then update the candidates
					out = vElectionUpdated;
					for (CandidateDto candidateDto : electionDto.getCandidateList()) {
						if (candidateDto.getCandidateId() > 0) {
							// candidate exists => update the candidate
							Validator vCandidateUpdated = editCandidate(candidateDto);

							out.setStatus(out.getStatus() + delimiter + vCandidateUpdated.getStatus());
							out.setVerified(out.isVerified() && vCandidateUpdated.isVerified());
						} else {
							// candidate does not exist => insert the candidate
							Validator vCandiateInserted = addCandidateToElection(candidateDto,
									electionDto.getElectionId());

							out.setStatus(out.getStatus() + delimiter + vCandiateInserted.getStatus());
							out.setVerified(out.isVerified() && vCandiateInserted.isVerified());
						}
					}

				} else {
					out = vElectionUpdated;
				}

			} else {
				out.setVerified(false);
				out.setStatus(vElection.getStatus());
			}
		}
		else
		{
			out.setVerified(false);
			out.setStatus("Election status is " + vElectionCurrent.getStatusCode() + ", does not allow to modify.");
		}
		return out;
	}

	/**
	 * @param candidateDto
	 *            - candidate object
	 * @author Steven Frink
	 */
	private Validator editCandidate(CandidateDto candidateDto) {
		PreparedStatement st = null;
		Validator val = new Validator();
		try {

			Validator vCandidate = candidateDto.Validate();
			if (vCandidate.isVerified()) {

				// String query =
				// "UPDATE candidate SET (candidate_name, display_order)=(?,?) WHERE candidate_id=?";
				String query = "UPDATE candidate "
						+ " SET candidate_name = ?, "
						+ " display_order = ? "
						+ " WHERE candidate_id = ?";
				st = this.con.prepareStatement(query, Statement.RETURN_GENERATED_KEYS);

				st.setString(1, candidateDto.getCandidateName());
				st.setInt(2, candidateDto.getDisplayOrder());
				st.setInt(3, candidateDto.getCandidateId());
				int updateCount = st.executeUpdate();
				if (updateCount > 0) {
					val.setStatus("Candidate updated successfully");
					val.setVerified(true);
				} else {
					val.setStatus("Failed to update candidate");
				}
			} else {
				val = vCandidate;
			}
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			val.setStatus("SQL Error");
			val.setVerified(false);
		}
		return val;
	}

	public Validator editCandidateStatus(CandidateDto cand) {
		PreparedStatement st = null;
		InputValidation iv = new InputValidation();
		Validator val = new Validator();
		try {
			val = iv.validateInt(cand.getStatus(), "Candidate Status");
			if (val.isVerified()) {
				String query = "UPDATE candidate SET status=? WHERE candidate_id=?";
				st = this.con.prepareStatement(query);
				st.setInt(1, cand.getCandidateId());
				st.execute();
				val.setStatus("Candidate status updated");
				return val;
			} else {
				val.setStatus("Status failed to verify");
				return val;
			}
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			val.setStatus("SQL Error");
			val.setVerified(false);
			return val;
		}
	}

	/*	*//**
	 * @param electionId
	 *            - the election to open Add candidates to an election
	 * @author Steven Frink
	 */
	/*
	 * public Validator openElection(int electionId) { PreparedStatement st =
	 * null; Validator val = new Validator();
	 * 
	 * try { String query = "UPDATE election" + " SET status=" +
	 * ElectionStatus.NEW.getCode() + " WHERE election_id=" + electionId; st =
	 * this.con.prepareStatement(query); st.execute(); val.setVerified(true);
	 * val.setStatus("Election opened"); return val; } catch (SQLException ex) {
	 * Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
	 * lgr.log(Level.WARNING, ex.getMessage(), ex); val.setStatus("SQL Error");
	 * val.setVerified(false); return val; } }
	 *//**
	 * @param electionId
	 *            - the election to close Close an election
	 * @author Steven Frink
	 */
	/*
	 * public Validator closeElection(int electionId) { PreparedStatement st =
	 * null; Validator val = new Validator(); try { String query =
	 * "UPDATE election" + " SET status=" + ElectionStatus.CLOSED.getCode() +
	 * " WHERE election_id=" + electionId; st =
	 * this.con.prepareStatement(query); st.execute(); val.setVerified(true);
	 * val.setStatus("Election closed"); return val; } catch (SQLException ex) {
	 * Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
	 * lgr.log(Level.WARNING, ex.getMessage(), ex); val.setVerified(false);
	 * val.setStatus("SQL Error"); return val; } }
	 *//**
	 * @param electionId
	 *            - the election to delete Delete an election
	 * @author Steven Frink
	 */
	/*
	 * public Validator deleteElection(int electionId) { PreparedStatement st =
	 * null; Validator val = new Validator(); try { String query =
	 * "UPDATE election SET status=7 WHERE election_id=" + electionId; st =
	 * this.con.prepareStatement(query); st.execute();
	 * val.setStatus("Election deleted"); val.setVerified(true); return val; }
	 * catch (SQLException ex) { Logger lgr =
	 * Logger.getLogger(DatabaseConnector.class.getName());
	 * lgr.log(Level.WARNING, ex.getMessage(), ex); val.setStatus("SQL Error");
	 * val.setVerified(false); return val; } }
	 */

	/**
	 * @param electionId
	 *            - the election id to update the status Delete an election
	 * @param electionStatus
	 *            - new status of the election
	 * @return validator - validator object with response of update operation
	 * @author Steven Frink
	 */
	public Validator editElectionStatus(int electionId, ElectionStatus electionStatus) {
		PreparedStatement st = null;
		Validator val = new Validator();
		try {
			String query = "UPDATE election" + " SET status=" + electionStatus.getCode() + " WHERE election_id="
					+ electionId;
			st = this.con.prepareStatement(query);
			st.execute();
			val.setStatus("Election status updated");
			val.setVerified(true);
			return val;
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			val.setStatus("SQL Error");
			val.setVerified(false);
			return val;
		}
	}

	/**
	 * @param electionDto
	 *            - the election to edit Edit an election
	 * @author Steven Frink
	 */
	private Validator editElection(ElectionDto electionDto) {
		PreparedStatement st = null;

		Validator val = new Validator();
		try {
			String query = "UPDATE election SET election_name=? WHERE election_id=?";

			st = this.con.prepareStatement(query, Statement.RETURN_GENERATED_KEYS);
			st.setString(1, electionDto.getElectionName());
			st.setInt(2, electionDto.getElectionId());
			st.executeUpdate();
			int updateCount = st.getUpdateCount();
			if (updateCount > 0) {
				val.setStatus("Election updated successfully");
				val.setVerified(true);
			} else {
				val.setStatus("Failed to update the election");
			}
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			val.setStatus("SQL Error");
			val.setVerified(false);
		}

		return val;
	}

	// Vote

	/**
	 * @param voteDto
	 *            - the vote to submit Submit a vote
	 * @author Steven Frink
	 */

	public Validator vote(VoteDto voteDto) {
		PreparedStatement st = null;
		Validator val = new Validator();

		if (voteDto.Validate().isVerified())
		{
			try {
				String query = "SELECT (user_id, election_id) FROM vote WHERE user_id=? AND election_id=?";
				st = this.con.prepareStatement(query);
				st.setInt(1, voteDto.getUserId());
				st.setInt(2, voteDto.getElectionId());
				ResultSet rs = st.executeQuery();
				SecurityValidator sec = new SecurityValidator();
				if (!rs.next()
						&& sec.checkSignature(voteDto.getVoteSignature(), voteDto.getVoteEncrypted(),
								voteDto.getUserId()).isVerified()) {
					query = "INSERT INTO vote (user_id, election_id, vote_encrypted, vote_signature)"
							+ " VALUES (?,?,?,?)";
					st = this.con.prepareStatement(query, Statement.RETURN_GENERATED_KEYS);
					st.setInt(1, voteDto.getUserId());
					st.setInt(2, voteDto.getElectionId());
					st.setString(3, voteDto.getVoteEncrypted());
					st.setString(4, voteDto.getVoteSignature());

					int updateCount = st.executeUpdate();
					if (updateCount > 0) {
						val.setStatus("Vote successfully cast");
						val.setVerified(true);
					} else {
						val.setStatus("Failed to cast vote");
					}

				} else {
					val.setStatus("invalid signature for this vote");
				}
			} catch (SQLException ex) {
				Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
				lgr.log(Level.WARNING, ex.getMessage(), ex);
				val.setStatus("SQL Error");
			}

		} else {
			val.setStatus("Vote information did not validate");
		}

		return val;

	}

	/**
	 * @param userDto
	 *            - userDetails with public key
	 * @return Validator - status of the public key update operation
	 * @author Hirosh Wickramasuriya
	 * 
	 */
	public Validator editUserPublicKey(UserDto userDto) {
		PreparedStatement st = null;
		Validator val = new Validator();

		String query = "UPDATE users SET public_key = ? WHERE user_id = ?";

		Validator vUserDto = userDto.Validate();

		if (vUserDto.isVerified()) {
			try {
				st = this.con.prepareStatement(query, Statement.RETURN_GENERATED_KEYS);
				st.setString(1, userDto.getPublicKey());
				st.setInt(2, userDto.getUserId());
				int updateCount = st.executeUpdate();
				if (updateCount > 0) {
					val.setStatus("User's public key updated successfully");
					val.setVerified(true);
				} else {
					val.setStatus("Failed to update the user's public key");
				}

			} catch (SQLException ex) {
				Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
				lgr.log(Level.WARNING, ex.getMessage(), ex);
				val.setStatus("SQL Error");
			}

		} else {
			val = vUserDto;
		}
		return val;
	}

	/**
	 * @param userDto
	 *            - userDto with the userId
	 * @return Validator - with user's public key
	 * @author Steven Frink
	 */
	public Validator selectUserPublicKey(UserDto userDto) {
		PreparedStatement st = null;
		Validator val = new Validator();

		InputValidation iv = new InputValidation();
		Validator vUserDto = iv.validateInt(userDto.getUserId(), "User ID");

		// Validator vUserDto = userDto.Validate();
		if (vUserDto.isVerified()) {
			String query = "SELECT public_key FROM users WHERE user_id = ?";

			try {
				st = this.con.prepareStatement(query);
				st.setInt(1, userDto.getUserId());
				ResultSet res = st.executeQuery();
				if (res.next()) {
					Blob pubKey = res.getBlob(1);
					byte[] pk = pubKey.getBytes(1, (int) pubKey.length());
					val.setObject(pk);
					val.setVerified(true);
					val.setStatus("Public key retrieved");

				} else {
					val.setStatus("No public key for this user id");
				}

			} catch (SQLException ex) {
				Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
				lgr.log(Level.WARNING, ex.getMessage(), ex);
				val.setStatus("SQL Error");
			}
		} else {
			val = vUserDto; // Failed to validate the user id
		}

		return val;
	}

	public Validator selectVotesByElectionId(int election_id) {
		Validator val = new Validator();
		InputValidation iv = new InputValidation();
		ArrayList<VoteDto> votes = new ArrayList<VoteDto>();
		Validator vElection = iv.validateInt(election_id, "Election ID");
		PreparedStatement st = null;
		try {
			if (vElection.isVerified()) {
				String query = "SELECT user_id, vote_encrypted, vote_signature, timestamp " + "	FROM vote "
						+ " WHERE election_id = ?";
				st = this.con.prepareStatement(query);
				st.setInt(1, election_id);
				ResultSet res = st.executeQuery();
				while (res.next()) {
					int user_id = res.getInt(1);
					String vote_encrypted = res.getString(2);
					String vote_signature = res.getString(3);
					Timestamp t = res.getTimestamp(4);

					VoteDto vote = new VoteDto();
					vote.setUserId(user_id);
					vote.setVoteEncrypted(vote_encrypted);
					vote.setVoteSignature(vote_signature);
					vote.setElectionId(election_id);
					vote.setTimestamp(t);

					votes.add(vote);
				}
				val.setStatus("Successfully retrieved votes");
				val.setObject(votes);
				val.setVerified(true);
			} else {
				val = vElection; // Failed to validate the election id
			}
		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
			val.setStatus("SQL Error");
		}
		return val;
	}

	public Validator tally(int election_id) {
		Map<CandidateDto, Integer> t = new HashMap<CandidateDto, Integer>();
		PreparedStatement st = null;
		Validator val = new Validator();
		InputValidation iv = new InputValidation();
		SecurityValidator sec = new SecurityValidator();
		Validator vElection = iv.validateInt(election_id, "Election ID");
		ArrayList<CandidateDto> cands = (ArrayList<CandidateDto>) selectCandidatesOfElection(election_id,
				Status.ENABLED).getObject();
		if (vElection.isVerified()) {
			Validator voteVal = selectVotesByElectionId(election_id);

			if (voteVal.isVerified()) {
				ArrayList<VoteDto> votes = (ArrayList<VoteDto>) voteVal.getObject();
				for (int i = 0; i < votes.size(); i++) {
					String enc = votes.get(i).getVoteEncrypted();
					String sig = votes.get(i).getVoteSignature();
					if (sec.checkSignature(sig, enc, votes.get(i).getUserId())
							.isVerified()) {
						int cand_id = Integer.parseInt(sec.decrypt(enc), 16);
						boolean validCand = false;
						for (int j = 0; j < cands.size(); j++) {
							if (cands.get(j).getCandidateId() == cand_id)
								validCand = true;
						}
						if (validCand) {
							CandidateDto cand = (CandidateDto) selectCandidate(
									cand_id).getObject();
							if (t.containsKey(cand)) {
								int total = t.get(cand);
								total += 1;
								t.remove(cand);
								t.put(cand, total);
							} else {
								t.put(cand, 1);
							}
						}
					}

				}
				val.setStatus("Tally computed");
				val.setObject(t);
				val.setVerified(true);

			} else {
				// val.setStatus(voteVal.getStatus());
				// val.setVerified(voteVal.isVerified());
				val = voteVal;
			}
		} else {
			val = vElection;
		}
		return val;
	}

	/**
	 * @param electionId
	 * @return Validator with ElectionDto that has results
	 * @author Steven Frink/Hirosh Wickramasuriya
	 */
	public Validator tally2(int electionId) {
		Map<Integer, CandidateDto> map = new HashMap<Integer, CandidateDto>();

		Validator val = new Validator();

		SecurityValidator sec = new SecurityValidator();
		ElectionDto electionDto = new ElectionDto();

		
		if (electionId > 0) {

			Validator vElection = selectElection(electionId);
			if (vElection.isVerified() ) {
				// get the election details
				electionDto = (ElectionDto) vElection.getObject();
				if (electionDto.getStatus() == ElectionStatus.CLOSED.getCode()) {
					// get the votes for this election 
					Validator voteVal = selectVotesByElectionId(electionId);

					if (voteVal.isVerified()) {
						
						ArrayList<CandidateDto> candidatesOfElection = (ArrayList<CandidateDto>)
								selectCandidatesOfElection(electionId, Status.ENABLED).getObject();		// all the candidates of the election
						
						// initialize the hashmap to have all the candidates
						for (CandidateDto candidate : candidatesOfElection) {
							map.put(candidate.getCandidateId(), candidate);
						}
						
						ArrayList<VoteDto> votes = (ArrayList<VoteDto>) voteVal.getObject();			// all the votes for the election
						
						// check the validity of each vote, decrypt and count the vote
						for (int i = 0; i < votes.size(); i++) {
							String enc = votes.get(i).getVoteEncrypted();
							String sig = votes.get(i).getVoteSignature();
							
							// check the signature of vote
							if (sec.checkSignature(sig, enc, votes.get(i).getUserId())
									.isVerified()) {
								
								byte[] plain=sec.hexStringtoByteArray(sec.decrypt(enc));
								String id=new String(plain);
								int cand_id = Integer.parseInt(id);
								boolean validCand = false;
								for (int j = 0; j < candidatesOfElection.size(); j++) {
									if (candidatesOfElection.get(j).getCandidateId() == cand_id) {
										validCand = true;
										break;
									}
								}
								
								if (validCand) {
									if (map.containsKey(cand_id)) {
										// candidateDto is in the Hashmap
										CandidateDto candidateDto = map.get(cand_id);
										int voteCount = candidateDto.getVoteCount() + 1;
										candidateDto.setVoteCount(voteCount);

										// replace the candidateDto in the Hashmap
										map.remove(cand_id);
										map.put(cand_id, candidateDto); // TODO: not sure without these twolines,
																		// value is udpated by reference

									} else {
										// this is a new candidateDto to the Hashmap
										CandidateDto candidateDto = (CandidateDto) selectCandidate(cand_id).getObject();
										candidateDto.setVoteCount(1); // First voted counted
										map.put(cand_id, candidateDto);
									}
								}
							}
						
						}

						// attach the candidates list with results to the ElectionDto
						ArrayList<CandidateDto> candidateResultList = new ArrayList<CandidateDto>();
						Iterator<Integer> iterator = map.keySet().iterator();

						while (iterator.hasNext()) {
							Integer key = iterator.next();
							CandidateDto candidateResult = map.get(key);
							candidateResultList.add(candidateResult);
						}

						electionDto.setCandidateList(candidateResultList);

						val.setStatus("Tally computed");
						val.setObject(electionDto);
						val.setVerified(true);

					} else {
						val = voteVal;
					}
				} else {
					val.setStatus("Election is not closed to tally the results");
				}
				
			} else {
				val = vElection;
			}
				
			
			
		} else {
			val.setStatus("Invalid Election Id");
		}
		return val;
	}

	/**
	 * @param electionId
	 * @return Validator with ElectionProgressDto
	 * @author Hirosh Wickramasuriya
	 */
	public Validator voteProgressStatusForElection(int electionId)
	{
		Validator val = new Validator();

		SecurityValidator sec = new SecurityValidator();
		ElectionProgressDto electionProgressDto = new ElectionProgressDto();

		if (electionId > 0) {
			electionProgressDto.setElectionId(electionId);
			Validator valVote = selectVotesByElectionId(electionId);

			if (valVote.isVerified()) {
				ArrayList<VoteDto> votes = (ArrayList<VoteDto>) valVote.getObject();
				electionProgressDto.setTotalVotes(votes.size());

				for (VoteDto voteDto : votes) {

					// check for the validity
					if (sec.checkSignature(voteDto).isVerified()) {
						// valid vote
						electionProgressDto.addValidVotes(1);

					} else {
						// rejected vote
						electionProgressDto.addRejectedVotes(1);
					}
				}

				// bind the final result to the validator
				val.setObject(electionProgressDto);
				val.setStatus("Election progress computed");
				val.setVerified(true);

			} else {
				val = valVote;
			}

		} else {
			val.setStatus("Invalid Election Id");
		}

		return val;
	}

	public Validator closeElectionAndPublishResults(int electionId) {
		Validator val = new Validator();
		Validator vElectionStatus = editElectionStatus(electionId, ElectionStatus.CLOSED);
		if (vElectionStatus.isVerified()) {
			Validator vResult = computeElectionResults(electionId);
			if (vResult.isVerified()) {
				vElectionStatus = editElectionStatus(electionId, ElectionStatus.PUBLISHED);
				if (vElectionStatus.isVerified()) {
					val.setStatus("Election results has been published");
					val.setVerified(true);
				} else {
					val = vElectionStatus;
				}

			} else {
				val = vResult;
			}
		} else {
			val = vElectionStatus;
		}

		return val;
	}

	private Validator computeElectionResults(int electionId) {
		Validator val = new Validator();

		if (electionId > 0) {
			Validator vElection = selectElection(electionId);
			if (vElection.isVerified()) {
				// check the election status
				ElectionDto electionDto = (ElectionDto) vElection.getObject();
				if (electionDto.getStatus() == ElectionStatus.CLOSED.getCode()) {

					// get the tallying results
					Validator vElectionTally = tally2(electionId);

					if (vElectionTally.isVerified()) {
						// Get the results for each candidates
						electionDto = (ElectionDto)vElectionTally.getObject();
						ArrayList<CandidateDto> candidates = electionDto.getCandidateList();
						boolean valid = true;
						for (CandidateDto candidate : candidates) {

							if (addResult(candidate) > 0) {
								// result has been added
								valid &= true;
							} else {
								// Failed to add the result

								// delete existing results if any
								deleteResults(electionDto.getElectionId());

								// set the validator
								val.setStatus("Failed to add results");
								valid &= false;
								break;
							}
						}

						val.setVerified(valid);
						if (valid) {
							val.setStatus("Results added successfully");

						} else {
							val.setStatus("Failed to add resulsts");
						}
					} else {
						val = vElectionTally;
					}

				} else {
					val.setStatus("Election is not closed to tally the results");
				}

			} else {
				val = vElection;
			}
		} else {
			val.setStatus("Invalid Election Id");
		}

		return val;
	}

	private int addResult(CandidateDto candidateDto) {

		PreparedStatement st = null;
		ResultSet rs = null;
		int newId = 0;

		try {
			String query = "INSERT INTO results (election_id, candidate_id, vote_count) VALUES (?,?,?)";

			st = this.con.prepareStatement(query, Statement.RETURN_GENERATED_KEYS);
			st.setInt(1, candidateDto.getElectionId());
			st.setInt(2, candidateDto.getCandidateId());
			st.setInt(3, candidateDto.getVoteCount());

			// update query
			st.executeUpdate();
			// get inserted id
			rs = st.getGeneratedKeys();
			rs.next();
			newId = rs.getInt(1);

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}

		return newId;
	}

	private boolean deleteResults(int electionId) {
		PreparedStatement st = null;
		ResultSet rs = null;
		boolean status = false;

		try {
			String query = "DELETE FROM results WHERE election_id = ?";

			st = this.con.prepareStatement(query, Statement.RETURN_GENERATED_KEYS);
			st.setInt(1, electionId);

			// update query
			if (st.executeUpdate() < 0) {
				// delete failed

			} else {
				// delete= sucessful
				status = true;
			}

		} catch (SQLException ex) {
			Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
			lgr.log(Level.WARNING, ex.getMessage(), ex);
		}
		return status;
	}

	public Validator selectResults(int electionId) {
		Validator val = new Validator();

		ElectionDto electionDto = new ElectionDto();
		ArrayList<CandidateDto> candidates = new ArrayList<CandidateDto>();

		PreparedStatement st = null;

		if (electionId > 0) {
			// valid election

			// Get the election details
			electionDto = (ElectionDto) selectElection(electionId).getObject();
			if (electionDto.getStatus() == ElectionStatus.PUBLISHED.getCode())
			{
				try {

					// get the results
					String query = "SELECT r.election_id, r.candidate_id, vote_count, candidate_name, display_order, status"
							+ " FROM results r"
							+ " INNER JOIN candidate c"
							+ " ON (r.candidate_id = c.candidate_id)"
							+ " WHERE r.election_id = ?";

					st = this.con.prepareStatement(query);
					st.setInt(1, electionId);

					ResultSet res = st.executeQuery();

					while (res.next()) {

						int resElectionId = res.getInt(1);
						int resCandidateId = res.getInt(2);
						int resVoteCount = res.getInt(3);
						String resCandiateName = res.getString(4);
						int resDisplayOrder = res.getInt(5);
						int resStatus = res.getInt(6);

						// populate candidates list
						CandidateDto candidateDto = new CandidateDto();
						candidateDto.setCandidateId(resCandidateId);
						candidateDto.setCandidateName(resCandiateName);
						candidateDto.setElectionId(resElectionId);
						candidateDto.setDisplayOrder(resDisplayOrder);
						candidateDto.setVoteCount(resVoteCount);
						candidateDto.setStatus(resStatus);

						candidates.add(candidateDto);
					}

					electionDto.setCandidateList(candidates); // attache
																// candidates
																// list to the
																// election

					// set the validator
					val.setVerified(true);
					val.setObject(electionDto);
					val.setStatus("Results selected successfully");

				} catch (SQLException ex) {
					Logger lgr = Logger.getLogger(DatabaseConnector.class.getName());
					lgr.log(Level.WARNING, ex.getMessage(), ex);
					val.setStatus("Select failed");
				}
			} else {
				val.setStatus("Election results has not been published");
			}

		} else {
			val.setStatus("Invalid Election Id");
		}

		return val;
	}
}
