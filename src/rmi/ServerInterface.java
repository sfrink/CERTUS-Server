package rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

import dto.Validator;

public interface ServerInterface extends Remote {
    public String sayHello(String name) throws RemoteException;   
    
    public Validator checkIfUsernamePasswordMatch(String email, String plainPass)
    		throws RemoteException;
}
