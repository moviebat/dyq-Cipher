package com.dyq.cipher.rsa;

import java.security.MessageDigest;


/**
 * sha256 hash
 * @author xiaoming 2017年3月21日
 */
public class SHA256Util {
    
    private static ThreadLocal<MessageDigest> digestThreadLocal = new ThreadLocal<MessageDigest>();// cipher
    // 线程局部变量
	/**
	 * sha256 hash提取
	 * @param text
	 * @return
	 * @author xiaoming
	 */
	public static String hash(String text) {
		byte[] digest = null;
		try {
			MessageDigest md = digestThreadLocal.get();
			if (md == null) {
				md = MessageDigest.getInstance("SHA-256");
				digestThreadLocal.set(md);
			}
			md.update(text.getBytes("UTF-8"));
			digest = md.digest();
		} catch (Exception e) {
			e.printStackTrace();
		}

		if (digest == null) {
			return null;
		}
		return bytesToHexString(digest);
	}
    /**
     * byte 数组转换成16进制
     * @param src
     * @return
     * @author xiaoming
     */
	private static String bytesToHexString(byte[] src) {
		StringBuilder stringBuilder = new StringBuilder("");
		if (src == null || src.length <= 0) {
			return null;
		}
		for (int i = 0; i < src.length; i++) {
			int v = src[i] & 0xFF;
			String hv = Integer.toHexString(v);
			if (hv.length() < 2) {
				stringBuilder.append(0);
			}
			stringBuilder.append(hv);
		}
		return stringBuilder.toString();
	}
	
}
