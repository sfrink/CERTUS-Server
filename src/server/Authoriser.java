package server;

import javax.security.sasl.AuthorizeCallback;

import rmi.CertusServer;
import database.DatabaseConnector;
import dto.Validator;

public class Authoriser {
	
	private static DatabaseConnector dbc;
		
	public Authoriser(DatabaseConnector dbCon){
		this.dbc = dbCon;
	}
	
	//get all the rights for a role:
	public static Validator getAllRoleRights(int roleID){
		return dbc.getRoleRights(roleID);
	}

	//get all the rights for a user:
	public static Validator getAllUserRights(int userID){
		Validator uV = dbc.getUserRoleByID(userID);
		
		if (uV.isVerified()){
			int userRoleID = (int) uV.getObject();
			return dbc.getRoleRights(userRoleID);
		}else{
			return uV;
		}
	}

	//Check if userID got access to elecionID:
	public static boolean gotAccessToElection(int userID, int electionID){
		return dbc.gotAccessToElection(userID, electionID);
	}
	
	//Check if userID is election authority on electionID:
	public static boolean isElectionAuth(int userID, int electionID){
		return dbc.isElectionAuth(userID, electionID);
	}
	
	//Check vote right:
	public static boolean isAllowedToVote(int requesterID, int voterID, int electionID){
		boolean res = false;
		
		//requesterID should have RightsGroup0 on vote action:
		res = gotRightsGroup0(requesterID, "vote");
		
		//requesterID should be the same as voterID:
		res &= (requesterID == voterID) ? true : false;
		
		//requesterID should be allowed to access electionID.
		res &= gotAccessToElection(requesterID, electionID);
		
		return res;
	}
	
	//Check view result right:
	public static boolean isAllowedToViewResults(int requesterID, int electionID){
		boolean res = false;
		
		//requesterID should have RightsGroup0 on view result action:
		res = gotRightsGroup0(requesterID, "selectResults");
		
		//requesterID should be allowed to access electionID.
		res &= gotAccessToElection(requesterID, electionID);

		return res;
	}
	
	//check if a user is allowed to invoke a method (by user id) RightsGroup0:
	public static boolean gotRightsGroup0  (int userID, String methodName){
		boolean allowed = false;
		
		int userRoleID = 0;
		int actionID = 0;
		
		//get the user role:
		Validator uV = dbc.getUserRoleByID(userID);
		if (uV.isVerified()){
			userRoleID = (int) uV.getObject();
		}else{
			return allowed;
		}
		
		//get the action id by the provided method name:
		Validator aV = dbc.getActionIDbyMethod(methodName);
		if (aV.isVerified()){
			actionID = (int) aV.getObject();
		}else{
			return allowed;
		}
		
		//check if this user role can invoke this action:
		Validator canBeInvoked = dbc.checkRoleRight(userRoleID, actionID);
		allowed = canBeInvoked.isVerified();
		
		return allowed;
	}

	
	//check if user got RightsGroup1:
	public static boolean gotRightsGroup1(int requesterID, int targetedUserID, String action){
		boolean res = false;
		
		//requesterID should have RightsGroup0 on the action.
		res = gotRightsGroup0(requesterID, action);
		
		//if requesterID is an admin: it got the right to do action regardless of the targetedUserID
		if (CertusServer.clientSessions.isAdmin(requesterID)){
			res &= true;
		}else if (CertusServer.clientSessions.isUser(requesterID)){
			//if requesterID is not admin: it got the right to do action if the targetedUserID is the same as the
			res &= (requesterID == targetedUserID) ? true : false;
		}
		
		return res;
	}
	
	//check if user got RightGroup2:
	public static boolean gotRightGroup2(int requesterID, int electionID, String action){
		boolean res = false;
		
		//requesterID should have RightsGroup0 on the action.
		res = gotRightsGroup0(requesterID, action);
		
		//if requesterID is an admin: it can apply action.
		if (CertusServer.clientSessions.isAdmin(requesterID)){
			res &= true;
		}else if (CertusServer.clientSessions.isUser(requesterID)){
			//if requesterID is not admin: it should be electionID Authority.
			res &= isElectionAuth(requesterID, electionID);			
		}

		return res;
	}
	
	
	
}
