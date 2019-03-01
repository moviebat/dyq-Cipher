package com.dyq.cipher.rsa;

import java.security.Provider;

import javax.crypto.Cipher;  
import javax.crypto.spec.IvParameterSpec;  
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加解密
 * @author xiaoming
 * 2017年5月22日
 */
public class AESUtil {
	private static ThreadLocal<Cipher> cipherThreadLocal = new ThreadLocal<Cipher>();//cipher 线程局部变量
	private static Provider provider = null;
    public static final String VIPARA = "aabbccddeeffgghh";   //AES 16bytes. DES 18bytes  
    public static final String bm = "UTF-8";
    
    static {
    	provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
    }
    /**
     *  加密
     * @param data
     * @param passwd
     * @return
     */
    public static String encryptByUTF8(String data, String passwd) {  
    	try {
    		return Base64Utils.encode(encrypt(data.getBytes(bm), passwd));
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return null;
    }    
    /**
     * 加密
     * @param data
     * @param passwd
     * @return
     * @author xiaoming
     */
    public static byte[] encrypt(byte[] data, String passwd) {  
        try {  
            IvParameterSpec zeroIv = new IvParameterSpec(VIPARA.getBytes());  
            SecretKeySpec key = new SecretKeySpec(getPass(passwd).getBytes(bm), "AES");  
            
            Cipher cipher = cipherThreadLocal.get();
			if(cipher == null){
				cipher = Cipher.getInstance("AES", provider);
				cipherThreadLocal.set(cipher);
			}
            cipher.init(Cipher.ENCRYPT_MODE, key, zeroIv);  
            byte[] encryptedData = cipher.doFinal(data);  
            return encryptedData;  
        } catch (Exception e) {  
            e.printStackTrace();
        }
        return null;
    }
    
    /**
     * 加密 只能加密Base64Utils 字符串
     * @param data
     * @param passwd
     * @return
     * @author xiaoming
     */
    public static String encrypt(String data, String passwd) { 
    	try {
    		return Base64Utils.encode(encrypt(data.getBytes("UTF-8"), passwd));
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return null;
    }
    
    /**
     * 解密  只能解密Base64Utils 字符串
     * @param encryptedData
     * @param passwd
     * @return
     * @author xiaoming
     */
    public static String decrypt(String encryptedData, String passwd) { 
    	try {
    		return new String((decrypt(Base64Utils.decode(encryptedData), passwd)), "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return null;
    }
    /**
     * 解密  utf8 字符串
     * @param encryptedData
     * @param passwd
     * @return
     */
    public static String decryptByUTF8(String encryptedData, String passwd){
    	try {
    		return new String(decrypt(Base64Utils.decode(encryptedData), passwd), bm);
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return null;
    }   
  
    /**
     * 解密
     * @param encryptedData
     * @param passwd
     * @return
     * @author xiaoming
     */
    public static byte[] decrypt(byte[] encryptedData, String passwd) {  
        try {  
            IvParameterSpec zeroIv = new IvParameterSpec(VIPARA.getBytes());  
            SecretKeySpec key = new SecretKeySpec(getPass(passwd).getBytes(bm), "AES");  
            Cipher cipher = cipherThreadLocal.get();
			if(cipher == null){
				cipher = Cipher.getInstance("AES", provider);
				cipherThreadLocal.set(cipher);
			}
            cipher.init(Cipher.DECRYPT_MODE, key, zeroIv);  
            byte[] decryptedData = cipher.doFinal(encryptedData);  
            return decryptedData;  
        } catch (Exception e) {  
            e.printStackTrace();  
            return null;  
        }  
    }
    /**
     * 密码长度为16
     * @param storePass
     * @return
     * @author xiaoming
     */
    private static String getPass(String storePass){
		if(storePass.length() < 16){
			char[] pass = new char[16];
			char[] pass_old = storePass.toCharArray();
			int i = 0;
			for(;i < pass_old.length;i++){
				pass[i] = pass_old[i];
			}
			for(;i < 16;i++){
				pass[i] = '0';
			}
			storePass = new String(pass);
		}else if(storePass.length() > 16){
			storePass = storePass.substring(0, 16);
		}
		return storePass;
    }
    
}  