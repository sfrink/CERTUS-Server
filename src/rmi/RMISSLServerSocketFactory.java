package rmi;


import java.io.*;
import java.net.*;
import java.rmi.server.*;

import javax.net.ssl.*;

import java.security.KeyStore;

import javax.net.ssl.*;

import dto.ConfigurationProperties;

public class RMISSLServerSocketFactory implements RMIServerSocketFactory {

    /*
     * Create one SSLServerSocketFactory, so we can reuse sessions
     * created by previous sessions of this SSLContext.
     */
    private SSLServerSocketFactory ssf = null;

    public RMISSLServerSocketFactory() throws Exception {
		try {
			// set up key manager to do server authentication
			SSLContext ctx;
			KeyManagerFactory kmf;
			KeyStore ks;

			String filePath = ConfigurationProperties.rmiBasePath();
			char[] passphrase = ConfigurationProperties.rmiPasswordKeystore().toCharArray();
			ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(filePath + ConfigurationProperties.rmiFileKeystore()), passphrase);
			
			kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, passphrase);

			ctx = SSLContext.getInstance("TLS");
			ctx.init(kmf.getKeyManagers(), null, null);

			ssf = ctx.getServerSocketFactory();
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
    }

    public ServerSocket createServerSocket(int port) throws IOException {
	    return ssf.createServerSocket(port);
    }

    public int hashCode() {
		return getClass().hashCode();
    }

    public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		return true;
    }
}