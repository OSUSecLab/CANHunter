package edu.osu.seclab.utility;

public class OtherUtility {
	public static boolean isInt(String s) {
		try {
			Integer.parseInt(s);
			return true;
		}

		catch (NumberFormatException er) {
			return false;
		}
	}

	public static int byteArrayToInt(byte[] b)
	{
		return   b[3] & 0xFF |
				(b[2] & 0xFF) << 8 |
				(b[1] & 0xFF) << 16 |
				(b[0] & 0xFF) << 24;
	}
}
