package dto;

import java.io.Serializable;

public class Validator implements Serializable {
	
	private boolean verified = false;
	private String status = "";
	private Object object = null;


	public Object getObject() {
		return object;
	}

	public void setObject(Object object) {
		this.object = object;
	}

	public boolean isVerified() {
		return verified;
	}

	public void setVerified(boolean verified) {
		this.verified = verified;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}
	
	public String toString() {
		String out = "";

		if (this.isVerified()) {
			out += "Verification passed";
		} else {
			out += "Verification failed: ";
			out += this.getStatus();
		}

		return out;
	}
}
