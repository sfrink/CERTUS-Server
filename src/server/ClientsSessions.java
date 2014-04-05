package server;

import java.util.ArrayList;
import java.util.UUID;

public class ClientsSessions {
	
	private ArrayList<Integer> usersID = new ArrayList<Integer>();
	private ArrayList<String> sessionsID = new ArrayList<String>();
	
	private String generateSessionID(){
		return UUID.randomUUID().toString();
	}
	
	
	public String addNewClient (int userID){
		String userSession = "";
		if (isLoggedIn(userID)){
			userSession = getSession(userID);
		}else{
			userSession = generateSessionID();
			usersID.add(userID);
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
		sessionsID.remove(index);
		
		return true;
	}
	
	public String toString(){
		String out = "";
		if (usersID.isEmpty()){
			return ("(No logged in users.)");
		}
		for (int i = 0; i < usersID.size(); i++){
			out += "(";
			out += sessionsID.get(i);
			out += " : ";
			out += usersID.get(i);
			out += ")";
			out += "\n";
		}
		return out;
	}
	

}
