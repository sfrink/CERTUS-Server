package dto;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Enumeration;

import enumeration.ElectionStatus;

/**
 * @date : Mar 16, 2014
 * @author : Hirosh Wickramasuriya
 */


public class ElectionDto implements Serializable{

	private int election_id;
	private String election_name;
	private int status;
	private Timestamp start_datetime;
	private Timestamp close_datetime;
	
	
	public int getElection_id() {
		return election_id;
	}
	public void setElection_id(int election_id) {
		this.election_id = election_id;
	}
	public String getElection_name() {
		return election_name;
	}
	public void setElection_name(String election_name) {
		this.election_name = election_name;
	}
	public int getStatus() {
		return status;
	}
	public String getStatusLabel()
	{
		return ElectionStatus.getStatus(this.status).getLabel();
	}
	public String getStatusDesc()
	{
		return ElectionStatus.getStatus(this.status).getDescription();
	}
	public void setStatus(int status) {
		this.status = status;
	}
	public Timestamp getStart_datetime() {
		return start_datetime;
	}
	public void setStart_datetime(Timestamp start_datetime) {
		this.start_datetime = start_datetime;
	}
	public Timestamp getClose_datetime() {
		return close_datetime;
	}
	public void setClose_datetime(Timestamp close_datetime) {
		this.close_datetime = close_datetime;
	}

	public String toString() {
		String out = "";
		String delimiter = "\n";
		String endOfString = "<<< end >>> \n";

		out += "Election " + delimiter;
		out += "id\t\t: " + this.getElection_id() + delimiter;
		out += "election name\t: " + this.getElection_name() + delimiter;
		out += "status\t\t: " + this.getStatus() + delimiter;
		out += "statusText\t: " + this.getStatusLabel() + delimiter;
		out += "statusDesc\t: " + this.getStatusDesc() + delimiter;
		out += "start date_time	: " + this.getStart_datetime() + delimiter;
		out += "close date_time	: " + this.getClose_datetime() + delimiter;
		
		out += endOfString;

		return out;
	}
	
}
