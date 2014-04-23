/**
 * @author Ahmad Kouraiem
 */
package database;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class BinFile {
	private static String path = "";
	private static File f;

	public BinFile(String fPath){
		f = new File(fPath);
	}
	
	public String getPath() {
		return path;
	}

	public boolean isFound(){
		boolean isFound = false;
		if(f.exists() && !f.isDirectory()) {
			isFound = true;
		}
		return isFound;
	}
		
	public boolean isDirectory(){
		boolean isDirectory = false;
		if(f.exists() && f.isDirectory()) {
			isDirectory = true;
		}
		return isDirectory;
	}
	
	public static byte[] readFile () throws IOException{
		byte [] fileByte = new byte[(int)f.length()];
		DataInputStream fileST = new DataInputStream((new FileInputStream(f)));
		fileST.readFully(fileByte);
		fileST.close();
		return fileByte;
	}

	public static void writeFile (String filePath, byte [] content) throws IOException{
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath));
		bos.write(content);
		bos.flush();
		bos.close();
	}
}
