package dto;

import java.io.Serializable;

import enumeration.CandidateStatus;
import enumeration.ElectionStatus;

/**
 * @date : Mar 16, 2014
 * @author : Hirosh Wickramasuriya
 */

public class CandidateDto implements Serializable{

	
	private int candidate_id;
	private String candidate_name;
	private int election_id;
	private int status;
	private int display_order;
	
	
	public int getCandidate_id() {
		return candidate_id;
	}
	public void setCandidate_id(int candidate_id) {
		this.candidate_id = candidate_id;
	}
	public String getCandidate_name() {
		return candidate_name;
	}
	public void setCandidate_name(String candidate_name) {
		this.candidate_name = candidate_name;
	}
	public int getElection_id() {
		return election_id;
	}
	public void setElection_id(int election_id) {
		this.election_id = election_id;
	}
	public int getStatus() {
		return status;
	}
	public String getStatusLabel()
	{
		return CandidateStatus.getStatus(this.status).getLabel();
	}
	public String getStatusDesc()
	{
		return CandidateStatus.getStatus(this.status).getDescription();
	}
	public void setStatus(int status) {
		this.status = status;
	}
	public int getDisplay_order() {
		return display_order;
	}
	public void setDisplay_order(int display_order) {
		this.display_order = display_order;
	}
	
	@Override
    public String toString() {
		String out = "";
		String delimiter = "\n";
		String endOfString = "<<< end >>> \n";

		out += "Candidate " + delimiter;
		out += "id\t\t: " + this.getCandidate_id() + delimiter;
		out += "candidate name\t: " + this.getCandidate_name() + delimiter;
		out += "status\t\t: " + this.getStatus() + delimiter;
		out += "statusText\t: " + this.getStatusLabel() + delimiter;
		out += "statusDesc\t: " + this.getStatusDesc() + delimiter;
		out += "election_id\t: " + this.getElection_id() + delimiter;
		out += "display_order\t: " + this.getDisplay_order() + delimiter;
		
		out += endOfString;

		return out;
	 }
}
