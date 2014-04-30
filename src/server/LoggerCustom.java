package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Timestamp;

public class LoggerCustom {

	public static void logRmiActivity(int userId, String action, boolean isPermited) {
		String delimiter = " | ";
		String newline = System.getProperty("line.separator");

		try {
			java.util.Date date = new java.util.Date();
			String timestamp = new Timestamp(date.getTime()).toString();

			String data = "";
			data += "UserId: " + userId + delimiter;
			data += "Action: " + action + delimiter;
			data += "Permision: " + isPermited + delimiter;
			data += "Timestamp: " + timestamp;
			data += newline;
				
			File file = new File(ConfigurationProperties.logFilename());

			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}

			// true = append file
			FileWriter fileWritter = new FileWriter(file.getName(), true);
			BufferedWriter bufferWritter = new BufferedWriter(fileWritter);
			bufferWritter.write(data);
			bufferWritter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
