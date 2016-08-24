package burp;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class CheckUtil {
	/**
	 * 验证检效码
	 * 
	 * @param checkParam
	 * @return
	 */
	public static String check(final HashMap<String, String> checkParam) {
		Map<String, String> order = new TreeMap<String, String>(checkParam);
		order.remove("cs");
		return calcChecksum(order);
	}
	
	
	/**
	 * md5
	 * @param b
	 * @return
	 */
	public static String byte2hexMd5(byte[] b) {
		String hs = "";
		String temp = "";
		for (int n = 0; n < b.length; n++) {
			temp = Integer.toHexString(b[n] & 0XFF);
			if (temp.length() == 1) {
				hs = hs + "0" + temp;
			} else {
				hs = hs + temp;
			}
		}

		return hs.toUpperCase();
	}

	private static String calcChecksum(Map<String, String> map) {
		String s = new String();
		Set<String> set = map.keySet();
		Iterator<String> iter = set.iterator();
		while (iter.hasNext()) {
			String key = iter.next();
			String value = map.get(key);
			s += key;
			s += "[";
			s += value;
			s += "];";
		}
		try {
			return getMD5Data(s);
		} catch (Exception e) {
			return null;
		}
	}

	private static String getMD5Data(String content) {
		try {
			byte[] src = content.getBytes(Charset.forName("UTF-8"));
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			md5.update(src);
			return byte2hexMd5(md5.digest()).toLowerCase();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	
	public static void main(String[] args) {
		System.out.println(getMD5Data("123456"));
	}

}
