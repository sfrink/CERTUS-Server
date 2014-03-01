package org.certus.server.rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface ServerInterface extends Remote {
    String sayHello(String name) throws RemoteException;
}
