package rmi;


import java.io.*;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.rmi.RMISecurityManager;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Properties;


public class CertusServer extends UnicastRemoteObject implements ServerInterface {

    private static int PORT;
    public static Properties prop;

    
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
    	
    	prop = getProperties();
    	PORT = Integer.parseInt(prop.getProperty("rmi_port"));
    	String filePath = prop.getProperty("rmi_basepath");
		System.setProperty("java.security.policy", filePath + prop.getProperty("rmi_file_policy"));
		
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
			registry.bind(prop.getProperty("rmi_registry"), obj);

			System.out.println("Certus Service bound in registry");
		} catch (Exception e) {
			System.out.println("Certus Server exception: " + e.getMessage());
			e.printStackTrace();
		}
    }
    
    
    public static Properties getProperties() {
		Properties prop = new Properties();
		InputStream input = CertusServer.class.getClassLoader().getResourceAsStream("config.properties");;
		
		try {
			// load a properties file
			prop.load(input);
	 
			// get the property value and print it out
			System.out.println(prop.toString());
			
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		
		return prop;
    }
}
