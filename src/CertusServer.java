

import java.io.*;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.RMISecurityManager;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;


public class CertusServer extends UnicastRemoteObject implements ServerInterface {

    private static final int PORT = 2019;

    public CertusServer() throws Exception {
		super(PORT, 
		new RMISSLClientSocketFactory(), 
		new RMISSLServerSocketFactory());
    }

    public String sayHello(String name) {
		System.out.println("Request received from the client: " + name);
		return "Hello Certus Client: " + name;
    }

    public static void main(String args[]) {
		
		System.setProperty("java.security.policy", "/Users/dkarmazi/Desktop/files/policy");
		
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
			registry.bind("CertusServer", obj);

			System.out.println("Certus Service bound in registry");
		} catch (Exception e) {
			System.out.println("Certus Server err: " + e.getMessage());
			e.printStackTrace();
		}
    }
}
