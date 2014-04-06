package rmi;


import java.io.FileInputStream;
import java.rmi.RMISecurityManager;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.cert.Certificate;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import server.Authoriser;
import server.ClientsSessions;
import server.ConfigurationProperties;
import server.SecurityValidator;
import database.DatabaseConnector;
import dto.ActionDto;
import dto.CandidateDto;
import dto.ElectionDto;
import dto.RightsListDto;
import dto.UserDto;
import dto.Validator;
import dto.VoteDto;
import enumeration.Status;
import enumeration.ElectionStatus;
import enumeration.UserStatus;


public class CertusServer extends UnicastRemoteObject implements ServerInterface {

    private static int PORT;
    private static DatabaseConnector dbc;
    private static SecurityValidator sec;
    
    public static Authoriser refMonitor;
    public static ClientsSessions clientSessions;

        
    public CertusServer() throws Exception {
		super(PORT, 
		new RMISSLClientSocketFactory(), 
		new RMISSLServerSocketFactory());
    }



    public static void main(String args[]) {
    	
    	
    	PORT = Integer.parseInt(ConfigurationProperties.rmiPort());
    	String filePath = ConfigurationProperties.rmiBasePath();
		System.setProperty("java.security.policy", filePath + ConfigurationProperties.rmiFilePolicy());
		
		// Create and install a security manager
		if (System.getSecurityManager() == null) {
			System.setSecurityManager(new RMISecurityManager());
		}

		try {
			// Create SSL-based registry
			Registry registry = LocateRegistry.createRegistry(PORT,
			new RMISSLClientSocketFactory(),
			new RMISSLServerSocketFactory());

			CertusServer obj = new CertusServer();

			// Bind this object instance to the name "CertusServer"
			registry.bind(ConfigurationProperties.rmiRegistry(), obj);

			dbc = new DatabaseConnector();
			sec = new SecurityValidator();
			refMonitor = new Authoriser(dbc);
			clientSessions = new ClientsSessions();
			
			System.out.println("Certus Service bound in registry");

			
		} catch (Exception e) {
			System.out.println("Certus RMI service exception: " + e.getMessage());
			e.printStackTrace();
		}
    }
    
    @Override
    public Validator checkIfUsernamePasswordMatch(String email, String plainPass)  throws RemoteException{
    	//Look up username in db, get salt, password hash
    	//DatabaseConnector db = new DatabaseConnector();
    	Validator validator = dbc.checkIfUsernamePasswordMatch(email, plainPass);
    	
//    	UserDto userDto=selectUserByEmailLimited(username);
//    	String hash=PasswordHasher.sha512(password,userDto.getSalt());
//    	return hash==userDto.getPassword();
    	return validator;
    	
    }
    
    public Validator addUser(UserDto userDto) throws RemoteException {
    	//anyone can invoke this method.
    	return dbc.addUser(userDto); 
    }
    
    public Validator selectUser(int userId, String sessionID) throws RemoteException {
    	
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectUser(userId);
        }
        
    	
    }
    
    public Validator selectAllUsers(String sessionID) throws RemoteException {
    	
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
    	   	return dbc.selectAllUsers();
        }
    }
    
    public Validator editUser(UserDto userDto, String sessionID) throws RemoteException {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.editUser(userDto);	
        }
    }
    
    public Validator editUserStatus(int userId, UserStatus userStatus, String sessionID) throws RemoteException {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.editUserStatus(userId, userStatus);
        }
    	
    	
    }
  
    
    public String sayHello(String name) {
		System.out.println("Request received from the client: " + name);
		return "Hello Certus Client: " + name;
    }
    
    // Election
    
    @Override
    public Validator selectElection(int id, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElection(id);
        }
    	
    }
    
    @Override
    public Validator selectElections(ElectionStatus electionStatus, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElections(electionStatus);
        }
    }
    
    @Override
    public Validator selectElectionsNotInStatus(ElectionStatus electionStatus, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElectionsNotInStatus(electionStatus);
        }
    }
    
    @Override
    public Validator selectElections(String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElections();
        }
    	
    }
    
    @Override
    public Validator selectElectionsOwnedByUser(int election_owner_id, ElectionStatus electionStatus, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElectionsOwnedByUser(election_owner_id, electionStatus);
        }
    }
    
    @Override
    public Validator selectElectionsOwnedByUser(int electionOwnerId, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return  dbc.selectElectionsOwnedByUser(electionOwnerId);
        }
    	
    }
    
    @Override
    public Validator addElection(ElectionDto electionDto, String sessionID)throws RemoteException {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.addElection(electionDto);
        }
    	
    }

    @Override
    public Validator editElection(ElectionDto electionDto, String sessionID)throws RemoteException {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.editElection(electionDto);
        }
    	
    }

    
    @Override
    public Validator editElectionStatus(int electionId, ElectionStatus electionStatus, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.editElectionStatus(electionId, electionStatus);
        }
    	
    }
    
    @Override
    public Validator openElectionAndPopulateCandidates(int electionId, String sessionID) throws RemoteException {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.openElectionAndPopulateCandidates(electionId);
        }
    	
    }
    
    // Candidate
    @Override
    public Validator selectCandidate(int id, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectCandidate(id);
        }
    	
 
    }
    
    @Override
    public Validator selectCandidatesOfElection(int electionId, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectCandidatesOfElection(electionId);
        }
    	
    	
    }
    
    @Override
    public Validator selectCandidatesOfElection(int electionId, Status candidateStatus, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return  dbc.selectCandidatesOfElection(electionId, candidateStatus);
        }
    }
    
    @Override
    public Validator editCandidateStatus(int candidateId, Status status, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	CandidateDto candidate = new CandidateDto();
        	candidate.setCandidateId(candidateId);
        	candidate.setStatus(status.getCode());
        	return dbc.editCandidateStatus(candidate);
        }
    }

    //Vote
    @Override
    public Validator vote(VoteDto v, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.vote(v);
        }
    	
    }
    
    @Override
    public Validator getTallierPublicKey() throws RemoteException{
//    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
//    	int clientID = clientSessions.getSession(sessionID);
//        boolean allowed = refMonitor.isAllowed(clientID, action);
//    	
//        if (!allowed){
//        	Validator res = new Validator();
//        	res.setVerified(false);
//        	res.setStatus("Permission denied.");
//        	return res;
//        }else{
//    	
//        	Validator res = new Validator();//to be deleted
//        	res.setVerified(false);//to be deleted
//        	res.setStatus("You are allowed to invoke.");//to be deleted
//        	return res;//to be deleted
//        }
    	
    	
    	sec=new SecurityValidator();
    	return sec.getTallierPublicKey();
    }
    
    @Override
    public Validator selectAllElectionsForVoter(int user_id, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectAllElectionsForVoter(user_id);
        }
    	
    }
    
    
    @Override
    public Validator voteProgressStatusForElection(int electionId, String sessionID) throws RemoteException {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.voteProgressStatusForElection(electionId);
        }
    	
    }
    
    @Override
    public Validator publishResults(int electionId, String sessionID) throws RemoteException {   	
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.publishResults(electionId);
        }
    	
    }
    
    @Override
    public Validator selectResults(int electionId, String sessionID) throws RemoteException {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int clientID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowed(clientID, action);
    	
        if (allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
    	
        	Validator res = new Validator();//to be deleted
        	res.setVerified(false);//to be deleted
        	res.setStatus("You are allowed to invoke.");//to be deleted
        	return res;//to be deleted
        }
//    	return dbc.selectResults(electionId);
    }
    
    @Override
    public boolean isAllowed(String sessionID, String method){
    	int userID = clientSessions.getSession(sessionID);
    	return refMonitor.isAllowed(userID, method);
    }
    
    
}
