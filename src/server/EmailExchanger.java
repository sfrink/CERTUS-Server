/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import java.io.File;
import java.io.IOException;
import java.util.Properties;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;
import javax.mail.BodyPart;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;

import dto.UserDto;

public class EmailExchanger {

	private static String username = "Certus.Voting@gmail.com";
	private static String password = "Deid*3@3ed";
	private static String newLine = System.getProperty("line.separator");

	/**
	 * This function sends an email to a given recipient with given subject and message and attach the byte array as a file.
	 */
	public static void sendEmailWithAttachement(String recepientAddress, String messageSubject, String messageBody, 
			byte[] attachmentContent,String attachmentFileName) {

		Properties props = new Properties();
		props.put("mail.smtp.starttls.enable", "true");
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.host", "smtp.gmail.com");
		props.put("mail.smtp.port", "587");

		Session session = Session.getInstance(props,
				new javax.mail.Authenticator() {
					protected PasswordAuthentication getPasswordAuthentication() {
						return new PasswordAuthentication(username, password);
					}
				});

		try {

			Message message = new MimeMessage(session);
			message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recepientAddress));
			message.setSubject(messageSubject);
			
			// Create the message part 
			BodyPart messageBodyPart = new MimeBodyPart();

			// Fill the message
			messageBodyPart.setText(messageBody);
			
			// Part two is attachment
			Multipart multipart = new MimeMultipart();
			multipart.addBodyPart(messageBodyPart);
			messageBodyPart = new MimeBodyPart();

			DataSource source = new ByteArrayDataSource(attachmentContent, "privateKey/bin");
			
			messageBodyPart.setDataHandler(new DataHandler(source));
			messageBodyPart.setFileName(attachmentFileName);
			multipart.addBodyPart(messageBodyPart);
	
			// Put parts in message
			message.setContent(multipart);
			
			// Send the message
			Transport.send(message);

		} catch (MessagingException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public static void sendEmail(String recepientAddress, String messageSubject, String messageBody) {

		Properties props = new Properties();
		props.put("mail.smtp.starttls.enable", "true");
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.host", "smtp.gmail.com");
		props.put("mail.smtp.port", "587");

		Session session = Session.getInstance(props,
				new javax.mail.Authenticator() {
					protected PasswordAuthentication getPasswordAuthentication() {
						return new PasswordAuthentication(username, password);
					}
				});

		try {

			Message message = new MimeMessage(session);
			message.setRecipients(Message.RecipientType.TO,	InternetAddress.parse(recepientAddress));
			message.setSubject(messageSubject);
			message.setText(messageBody);

			Transport.send(message);

		} catch (MessagingException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static String getInvitationSubject(){
		return "Invitation from CERTUS";
	}
	public static String getInvitationBody(UserDto userDto){
		String body = "";
		
		body = "Dear user," + newLine;
		body += newLine;
		body += "You have been invited to register the CERTUS voting system.";
		body += newLine;
		body += "Please use the following url to access the system.";
		body += newLine + "URL :" + ConfigurationProperties.emailSystemUrl();
		body += newLine;
		body += newLine + "Your user name \t\t:" + userDto.getEmail();
		body += newLine + "Your temporary password :" + userDto.getPassword();
		body += newLine + "You must change your password at your first login.";
		body += newLine;
		body += newLine + "Thank you";
		body += newLine + "Election Administrator";
		body += newLine + "CERTUS Voting";
		body += newLine;
		body += newLine;
		body += newLine + "NOTE: This is a system generated message. Please do not reply this email.";
		return body;
	}
	
	public static String getNotificationBody(UserDto userDto, String electionName){
		String body = "";
		String name = "user,";
		if ((userDto.getFirstName() != null ) && (userDto.getLastName() != null )){
			name = userDto.getFirstName() + " " + userDto.getLastName() +",";
		}
		
		body = "Dear "+ name + newLine;
		body += newLine;
		body += "You have been invited to vote the private election '" + electionName + "'.";
		body += newLine;
		body += "Please use the following url to access the system.";
		body += newLine + "URL :" + ConfigurationProperties.emailSystemUrl();
		body += newLine;
		body += newLine + "Your user name \t\t:" + userDto.getEmail();
		body += newLine;
		body += newLine + "Thank you";
		body += newLine + "Election Administrator ";
		body += newLine + "CERTUS Voting";
		body += newLine;
		body += newLine;
		body += newLine + "NOTE: This is a system generated message. Please do not reply this email.";
		body += newLine;
		return body;
	}

}
