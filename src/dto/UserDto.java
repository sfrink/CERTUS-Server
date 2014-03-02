package dto;

import java.io.Serializable;

public class UserDto implements Serializable {
	
	private int user_id;
	private String first_name;
	private String last_name;
	private String email;
	private String password;
	private String salt;
	private String temp_password;
	private String temp_salt;
	private String activation_code;
	private String public_key;
	private int administrator_flag;
	private int status;
	
	public int getUser_id() {
		return user_id;
	}
	public void setUser_id(int user_id) {
		this.user_id = user_id;
	}
	public String getFirst_name() {
		return first_name;
	}
	public void setFirst_name(String first_name) {
		this.first_name = first_name;
	}
	public String getLast_name() {
		return last_name;
	}
	public void setLast_name(String last_name) {
		this.last_name = last_name;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getSalt() {
		return salt;
	}
	public void setSalt(String salt) {
		this.salt = salt;
	}
	public String getTemp_password() {
		return temp_password;
	}
	public void setTemp_password(String temp_password) {
		this.temp_password = temp_password;
	}
	public String getTemp_salt() {
		return temp_salt;
	}
	public void setTemp_salt(String temp_salt) {
		this.temp_salt = temp_salt;
	}
	public String getActivation_code() {
		return activation_code;
	}
	public void setActivation_code(String activation_code) {
		this.activation_code = activation_code;
	}
	public String getPublic_key() {
		return public_key;
	}
	public void setPublic_key(String public_key) {
		this.public_key = public_key;
	}
	public int getAdministrator_flag() {
		return administrator_flag;
	}
	public void setAdministrator_flag(int administrator_flag) {
		this.administrator_flag = administrator_flag;
	}
	public int getStatus() {
		return status;
	}
	public void setStatus(int status) {
		this.status = status;
	}
	
	public String toString() {
		String out = "";
		String delimiter = "\n";
		String endOfString = "\n\n";

		out += "User ";
		out += "id: " + this.getUser_id() + delimiter;
		out += "first name: " + this.getFirst_name() + delimiter;
		out += "last name: " + this.getLast_name() + delimiter;
		out += "email: " + this.getEmail() + delimiter;
		out += "password: " + this.getPassword() + delimiter;
		out += "salt: " + this.getSalt() + delimiter;
		out += "temp_pass: " + this.getTemp_password() + delimiter;
		out += "temp_salt: " + this.getTemp_salt() + delimiter;
		out += "activation_code: " + this.getActivation_code() + delimiter;
		out += "public key: " + this.getPublic_key() + delimiter;
		out += "admin_flag: " + this.getAdministrator_flag() + delimiter;
		out += "status: " + this.getStatus() + delimiter;

		out += endOfString;

		return out;
	}
}