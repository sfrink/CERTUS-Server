package rmi;


import java.io.*;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.RMISecurityManager;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.Properties;

import database.DatabaseConnector;
import dto.*;
import enumeration.CandidateStatus;
import enumeration.ElectionStatus;
import server.PasswordHasher;


public class CertusServer extends UnicastRemoteObject implements ServerInterface {

    private static int PORT;
    private static DatabaseConnector dbc;

    
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
    

    public String sayHello(String name) {
		System.out.println("Request received from the client: " + name);
		return "Hello Certus Client: " + name;
    }
    
    // Election
    
    @Override
    public ElectionDto getElection(int id) throws RemoteException{
    	return dbc.selectElection(id);
    }
    
    @Override
    public ArrayList<ElectionDto> getElections(ElectionStatus electionStatus) throws RemoteException{
    	return dbc.selectElections(electionStatus);
    }
    
    
    @Override
    public ArrayList<ElectionDto> getElections() throws RemoteException{
    	return dbc.selectElections();
    }
    
    // Candidate
    
    @Override
    public CandidateDto getCandidate(int id) throws RemoteException{
    	return dbc.selectCandidate(id);
    }
    
    @Override
    public ArrayList<CandidateDto> getCandidatesOfElection(int election_id) throws RemoteException{
    	return dbc.selectCandidatesOfElection(election_id);
    }
    
    @Override
    public ArrayList<CandidateDto> getCandidatesOfElection(int election_id, CandidateStatus candidateStatus) throws RemoteException{
    	return dbc.selectCandidatesOfElection(election_id, candidateStatus);
    }
}