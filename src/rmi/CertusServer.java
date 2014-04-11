package rmi;


import java.io.FileInputStream;
import java.io.InputStream;
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
    	if (validator.isVerified()){
    		UserDto user = (UserDto) validator.getObject();
    		
    		user.setSessionId(clientSessions.addNewClient(user));

    		validator.setObject(user);    		
    	}
    	return validator;
    }
    
    public Validator addUser(UserDto userDto) throws RemoteException {
    	//anyone can invoke this method.
    	return dbc.addUser(userDto); 
    }
    
    public Validator selectUser(int userId, String sessionID) throws RemoteException {
    	
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup1(requesterID, userId, action);        
        
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectUser(userId);
        }
    }
    
    public Validator addAdditionalUsersToElection(ElectionDto electionDto, String sessionID) throws RemoteException {
    	
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup2(requesterID, electionDto.getElectionId(), action);        
        allowed = true;
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.addAdditionalUsersToElection(electionDto);
        }
        
    	
    }
    public Validator selectAllUsers(String sessionID) throws RemoteException {
    	
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup0(requesterID, action);
    	
        if (!allowed){
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
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup1(requesterID, userDto.getUserId(), action);
    	
        if (!allowed){
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
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup0(requesterID, action);
    	
        if (!allowed){
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
    
    
    @Override
    public Validator selectElectionForOwner(int electionId, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup2(requesterID, electionId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElectionForOwner(electionId);
        }    	
    }

    @Override
    public Validator selectElectionForVoter(int electionId, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowedToVote(requesterID, requesterID, electionId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElectionForVoter(electionId);
        }    	
    }

    
    
    
    
    
    @Override
    public Validator selectElectionFullDetail (int electionId, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup2(requesterID, electionId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElectionFullDetail(electionId);
        }
    	
    }
    
    @Override
    public Validator selectElectionsForAdmin(String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup0(requesterID, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElectionsForAdmin();
        }
    }
    
    
    @Override
    public Validator selectElectionsForResults(int userId, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup1(requesterID, userId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElectionsForResults(userId);
        }
    }
    
    @Override
    public Validator selectElectionsForOwner(int electionOwnerId, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup1(requesterID, electionOwnerId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return  dbc.selectElectionsForOwner(electionOwnerId);
        }
    	
    }
    
    @Override
    public Validator addElection(ElectionDto electionDto, String sessionID)throws RemoteException {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup0(requesterID, action);
    	
        if (!allowed){
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
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup2(requesterID, electionDto.getElectionId(), action);
    	
        if (!allowed){
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
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup2(requesterID, electionId, action);
    	
        if (!allowed){
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
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup2(requesterID, electionId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.openElectionAndPopulateCandidates(electionId);
        }
    	
    }
    
    //Vote
    @Override
    public Validator vote(VoteDto v, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowedToVote(requesterID, v.getUserId(), v.getElectionId(), action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.vote(v);
        }
    	
    }
    
    @Override
    public Validator getTallierPublicKey(int electionId, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowedToVote(requesterID, requesterID, electionId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.getTallierPublicKey(electionId);
        }
    	
    }
    
    @Override
    public Validator selectElectionsForVoter(int userId, String sessionID) throws RemoteException{
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup1(requesterID, userId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectElectionsForVoter(userId);
        }
    	
    }
    
    
    @Override
    public Validator voteProgressStatusForElection(int electionId, String sessionID) throws RemoteException {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowedToViewResults(requesterID, electionId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.voteProgressStatusForElection(electionId);
        }
    	
    }
    
    @Override
    public Validator publishResults(int electionId, String password, String sessionID) throws RemoteException {   	
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup2(requesterID, electionId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.publishResults(electionId, password);
        }
    	
    }
    
    @Override
    public Validator selectResults(int electionId, String sessionID) throws RemoteException {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.isAllowedToViewResults(requesterID, electionId, action);
    	
        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.selectResults(electionId);
        }
    	
    }
    
    @Override
    public Validator registerNewUser (UserDto userDto){
    	return dbc.registerNewUser(userDto);
    }
    
    @Override
    public Validator generateNewKeys(int userID, String newKeyPass, String sessionID) {
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup1(requesterID, userID, action);

        if (!allowed){
        	Validator res = new Validator();
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.generateNewKeys(userID, newKeyPass);
        	
        }
    }
    
    @Override
    public Validator logOut(String sessionID){
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup0(requesterID, action);

        Validator res = new Validator();
        if (!allowed){
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	boolean done = clientSessions.removeClient(sessionID);
        	res.setVerified(done);
        	if (done){
        		res.setStatus("Log out succeeded");
        	}else{
        		res.setStatus("Log out faild");
        	}
        }
        return res;
    }
    
    @Override
    public Validator updateUser(UserDto userDto, String sessionID){
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup1(requesterID, requesterID, action);

        Validator res = new Validator();
        if (!allowed){
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	userDto.setUserId(requesterID);
        	return dbc.updateUser(userDto);
        }
        
    }
    
    @Override
    public Validator updateUserPassword(UserDto userDto, String sessionID){
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup1(requesterID, userDto.getUserId(), action);

        userDto.setUserId(requesterID);
        Validator res = new Validator();
        if (!allowed){
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	//check if the current password is correct for the user:
        	boolean correct = dbc.checkCorrectPassword(requesterID, userDto.getPassword());
        	
        	if (correct){
        		//the password matched, we can update it now:
        		res = dbc.updateUserPassword(userDto);
        	}else{
        		//the password didn't match, we cannot update the password:
        		res.setVerified(false);
        		res.setStatus("old password is not correct.");
        	}
        	
        	return res;
        }    	
    }


    @Override
    public Validator uploadPubKey(byte[] keyBytes, String sessionID){
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup1(requesterID, requesterID, action);    
        
        Validator res = new Validator();
        
        if (keyBytes.length > 10240){
        	res.setVerified(false);
        	res.setStatus("Large file");
        }else if (!allowed){
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        }else{
        	res = dbc.uploadPubKey(keyBytes, requesterID);        	
        }    	
        
        return res;
    }
    
    @Override
    public Validator deleteElection(int electionId, String sessionID){
    	String action = Thread.currentThread().getStackTrace()[1].getMethodName();
    	int requesterID = clientSessions.getSession(sessionID);
        boolean allowed = refMonitor.gotRightsGroup0(requesterID, action);

        Validator res = new Validator();
        if (!allowed){
        	res.setVerified(false);
        	res.setStatus("Permission denied.");
        	return res;
        }else{
        	return dbc.deleteElection(electionId);
        }

    }
    
    
}
