package server;

import database.DatabaseConnector;
import dto.Validator;

public class Authoriser {
	
	private static DatabaseConnector dbc;
		
	public Authoriser(DatabaseConnector dbCon){
		this.dbc = dbCon;
	}

	//check if a user is allowed to invoke a method (by user id):
	public boolean isAllowed (int userID, String methodName){
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
	
}
