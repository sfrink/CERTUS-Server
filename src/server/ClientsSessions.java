package server;

import java.util.ArrayList;
import java.util.UUID;

import dto.UserDto;

public class ClientsSessions {
	
	private ArrayList<Integer> usersID = new ArrayList<Integer>();
	private ArrayList<Integer> usersRole = new ArrayList<Integer>();
	private ArrayList<String> sessionsID = new ArrayList<String>();
	
	private String generateSessionID(){
		return UUID.randomUUID().toString();
	}
	
	
	public String addNewClient (UserDto user){
		String userSession = "";
		
		int userID = user.getUserId();
		int isAdmin = user.getType();
		
		if (isLoggedIn(userID)){
			userSession = getSession(userID);
		}else{
			userSession = generateSessionID();
			usersID.add(userID);
			usersRole.add(isAdmin);
			sessionsID.add(userSession);
		}
				
		return userSession;
	}
	
	public boolean isLoggedIn (String sessionID){
		return sessionsID.contains(sessionID);
	}
	
	public boolean isLoggedIn (int userID){
		return usersID.contains(userID);
	}
	
	public String getSession (int userID){
		int index = usersID.indexOf(userID);
		if (index != -1){
			return sessionsID.get(index);
		}else{
			return "";
		}
	}
	
	public int getSession (String sessionID){
		int index = sessionsID.indexOf(sessionID);
		if (index != -1){
			return usersID.get(index);
		}else{
			return -1;
		}
	}
	
	public boolean removeClient (String sessionID){
		int index = sessionsID.indexOf(sessionID);
		
		//if session is not found:
		if (index == -1){
			return false;
		}
		
		usersID.remove(index);
		usersRole.remove(index);
		sessionsID.remove(index);
				
		return true;
	}
	
	public boolean isAdmin(int userID){
		int index = usersID.indexOf(userID);
		
		//if session is not found:
		if (index == -1){
			return false;
		}
		
		if (usersRole.get(index) == 1){
			return true;
		}else{
			return false;
		}
		
	}
	
	public boolean isAdmin(String sessionID){
		int index = sessionsID.indexOf(sessionID);
		
		//if session is not found:
		if (index == -1){
			return false;
		}
		
		if (usersRole.get(index) == 1){
			return true;
		}else{
			return false;
		}
		
	}
	
	public boolean isUser(int userID){
		int index = usersID.indexOf(userID);
		
		//if session is not found:
		if (index == -1){
			return false;
		}
		
		if (usersRole.get(index) == 0){
			return true;
		}else{
			return false;
		}
	}
	
	public boolean isUser(String sessionID){
		int index = sessionsID.indexOf(sessionID);
	
		//if session is not found:
		if (index == -1){
			return false;
		}
		
		if (usersRole.get(index) == 0){
			return true;
		}else{
			return false;
		}	
	}
	
	
	public String toString(){
		String out = "";
		if (usersID.isEmpty()){
			return ("(No logged in users.)");
		}
		for (int i = 0; i < usersID.size(); i++){
			out += "(User ID: " + usersID.get(i);
			out += " | ";
			out += "User Role: " + usersRole.get(i);
			out += " | ";
			out += "User Session: " + sessionsID.get(i);
			out += ")\n";
		}
		return out;
	}
	

}
