package server;

//import java.sql.Timestamp;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dto.Validator;


public class InputValidator {

	
	public Validator validateEmail(String str, String label) {
		String delimiter = "\n";
		Validator v = new Validator();

		Pattern pattern = Pattern
				.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
						+ "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");
		Matcher matcher = pattern.matcher(str);

		v.setVerified(false);
		v.setStatus(label + " is not an email of proper form" + delimiter);

		if (matcher.matches()) {
			v.setVerified(true);
			v.setStatus("");
		}

		return v;
	}
	
	public Validator validateString(String str, String label, int maxLength) {
		
		String delimiter = "\n";

		Validator v = new Validator();
		v.setVerified(true);
		v.setStatus("");

		if (str.isEmpty()) {
			v.setVerified(false);
			v.setStatus(label + " field cannot be empty" + delimiter);
		} else if (str.length() > maxLength) {
			v.setVerified(false);
			v.setStatus(label + " length cannot be longer than " + maxLength
					+ " characters" + delimiter);
		}

		return v;
	}
	
	public Validator validateString(String str, String label) {
		
		String delimiter = "\n";

		Validator v = new Validator();
		v.setVerified(true);
		v.setStatus("");

		if (str.isEmpty()) {
			v.setVerified(false);
			v.setStatus(label + " field cannot be empty" + delimiter);
		}

		return v;
	}

}

