

import java.io.*;
import java.net.*;
import java.rmi.server.*;
import javax.net.ssl.*;

public class RMISSLClientSocketFactory
	implements RMIClientSocketFactory, Serializable {

    public Socket createSocket(String host, int port) throws IOException {
	    SSLSocketFactory factory =
		(SSLSocketFactory)SSLSocketFactory.getDefault();
	    SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
	    return socket;
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
