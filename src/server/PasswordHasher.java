import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class PasswordHasher implements Serializable {

	public static String toHex(byte[] hashValue) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < hashValue.length; i++) {
			sb.append(Integer.toString((hashValue[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return sb.toString();
	}

	public static String generateSalt() {
		SecureRandom random = new SecureRandom();
		String randSalt = new BigInteger(32, random).toString(32);
		randSalt = randSalt.substring(0, 4);
		return randSalt;
	}

	public String sha512(String pwd, String salt) {
		try {
			MessageDigest sha = MessageDigest.getInstance("SHA-512");

			byte[] b = (pwd + salt).getBytes();

			byte[] hash = sha.digest(b);

			return toHex(hash);

		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Hash test failed");
			return null;
		}
	}

	public static String generateRandomString() {
		SecureRandom random = new SecureRandom();

		String randPass = new BigInteger(48, random).toString(32);

		return randPass;
	}

}