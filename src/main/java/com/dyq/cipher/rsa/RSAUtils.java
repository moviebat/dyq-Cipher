package com.dyq.cipher.rsa;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

import com.dyq.cipher.util.ArrayUtils;

/**
 * RSA加密解密工具
 * @author xiaoming
 * 2017年2月4日
 */
public class RSAUtils {
	private static ThreadLocal<Signature> signatureThreadLocal = new ThreadLocal<Signature>();//signature 线程局部变量
	private static ThreadLocal<Cipher> cipherThreadLocal = new ThreadLocal<Cipher>();//cipher 线程局部变量
	private static String ALGORITHM = "RSA";
	private static String SIGNATURE_ALGORITHM = "SHA256withRSA";
	private static Provider provider = null;
	
	 /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;
    
    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;
    
    static{
    	provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
    	Security.addProvider(provider);
    }
    
    /**
     * 签名函数,byte数组最终以16进制显示
     * @param text 明文
     * @param privateKey
     * @return
     * @author xiaoming
     */
    public static String signName(String text,PrivateKey privateKey){
    	String signText = null;
    	try {
    		Signature signature = signatureThreadLocal.get();
    		if(signature == null){
    			signature = Signature.getInstance(SIGNATURE_ALGORITHM);
    			signatureThreadLocal.set(signature);
    		}
			signature.initSign(privateKey);//私钥
			signature.update(text.getBytes("UTF-8"));
			signText = Base64Utils.encode(signature.sign());
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return signText;
    }
    
    /**
     * 验签
     * @param signText 签名后的密文
     * @param text  明文
     * @param publicKey
     * @return
     * @author xiaoming
     */
    public static boolean verify(String signText, String text, PublicKey publicKey){
		boolean signValue = false;
    	try {
    		Signature signature = signatureThreadLocal.get();
    		if(signature == null){
    			signature = Signature.getInstance(SIGNATURE_ALGORITHM);
    			signatureThreadLocal.set(signature);
    		}
			signature.initVerify(publicKey);
			signature.update(text.getBytes("UTF-8"));
			signValue = signature.verify(Base64Utils.decode(signText));
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return signValue;
    }
    
    
	/**
	 * RSA加密
	 * 2017年2月4日 xiaoming
	 * @param data
	 * @param key
	 * @return
	 */
	public static byte[] encrypt(byte[] data, Key key){
		byte[] enBytes = null;
		try {
			Cipher cipher = cipherThreadLocal.get();
			if(cipher == null){
				//TODO 王要军 李欣
//				cipher = Cipher.getInstance(ALGORITHM, provider);
//				cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
				cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", provider);
				cipherThreadLocal.set(cipher);
			}
			
			cipher.init(Cipher.ENCRYPT_MODE, key);
			for (int i = 0; i < data.length; i += 116) {
				//批次加密防止超出字节117
				byte[] tmpData = cipher.doFinal(ArrayUtils.subarray(data, i,i + 116));
				enBytes = ArrayUtils.addAll(enBytes, tmpData);
			}
			return enBytes;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * RSA加密
	 * 2017年2月4日 xiaoming
	 * @param data
	 * @param key
	 * @return
	 */
	public static String encryptByString(String data, Key key){
		try {
			return Base64Utils.encode((encrypt(data.getBytes("UTF-8"), key)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * RSA解密
	 * 2017年2月4日 xiaoming
	 * @param data
	 * @param key
	 * @return
	 */
    public static byte[] decrypt(byte[] data, Key key){
    	byte[] enBytes = null;
		try {
			Cipher cipher = cipherThreadLocal.get();
			if(cipher == null){
//				cipher = Cipher.getInstance(ALGORITHM, provider);
//				cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
				cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", provider);
				cipherThreadLocal.set(cipher);
			}
			cipher.init(Cipher.DECRYPT_MODE, key);
			for (int i = 0; i < data.length; i += 128) {  
				//分批解密防止超出128位
				byte[] tmpData = cipher.doFinal(ArrayUtils.subarray(data, i,i + 128));
				enBytes = ArrayUtils.addAll(enBytes, tmpData);
			}
			return enBytes;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
    
    /**
     * RSA解密
     * 2017年2月4日 xiaoming
     * @param data
     * @param key
     * @return
     * @throws Exception 
     */
    public static String decryptToString(String data, Key key){
		try {
			return new String(decrypt(Base64Utils.decode(data), key), "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
    }
    
    /**
     * <p>
     * 用私钥对信息生成数字签名
     * </p>
     * 
     * @param data 已加密数据
     * @param privateKey 私钥(BASE64编码)
     * 
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64Utils.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = signatureThreadLocal.get();
		if(signature == null){
			signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signatureThreadLocal.set(signature);
		}
        signature.initSign(privateK);
        signature.update(data);
        return Base64Utils.encode(signature.sign());
    }
    /**
     * 
     * @param privateKey
     * @return
     * @throws Exception
     * @author xiaoming
     */
    public static PrivateKey getPrivateKey(String privateKey) throws Exception{
    	 byte[] keyBytes = Base64Utils.decode(privateKey);
         PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
         KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
         return keyFactory.generatePrivate(pkcs8KeySpec);
    }
    
    /**
     * 
     * @param publicKey
     * @return
     * @throws Exception
     * @author xiaoming
     */
    public static PublicKey getPublicKey(String publicKey) throws Exception{
    	byte[] keyBytes = Base64Utils.decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(keySpec);
   }
    
    /**
     * <p>
     * 校验数字签名
     * </p>
     * 
     * @param data 已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign 数字签名
     * 
     * @return
     * @throws Exception
     * 
     */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = signatureThreadLocal.get();
		if(signature == null){
			signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signatureThreadLocal.set(signature);
		}
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64Utils.decode(sign));
    }
    
    
    /** *//**
     * <p>
     * 公钥加密
     * </p>
     * 
     * @param data 源数据
     * @param publicKey 公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKey(byte[] data, String publicKey)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding",keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return Base64Utils.encode(encryptedData);
    }
    
    /**
     * <P>
     * 私钥解密
     * </p>
     * 
     * @param encryptedData 已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey)
            throws Exception {
        byte[] keyBytes = Base64Utils.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        //AES/CTR/PKCS5Padding  RSA/ECB/PKCS1Padding
//        Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding",keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }
    
    /**
     * 生成公钥私钥
     * 2017年2月4日 xiaoming
     * @return
     */
    public static KeyPair generateKeyPair(){
    	KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance(ALGORITHM,"BC");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		kpg.initialize(1024, new SecureRandom());
		KeyPair kp = kpg.generateKeyPair();
    	return kp;
    }
    
    /**
	 * byte[] to Convert hex string
	 * 
	 * @param hexString
	 *            the hex string
	 * @return byte[]
	 */
    public static String bytesToHexString(byte[] src) {
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

	/**
	 * Convert hex string to byte[]
	 * 
	 * @param hexString
	 *            the hex string
	 * @return byte[]
	 */
	public static byte[] hexStringToBytes(String hexString) {
		if (hexString == null || hexString.equals("")) {
			return null;
		}
		hexString = hexString.toUpperCase();
		int length = hexString.length() / 2;
		char[] hexChars = hexString.toCharArray();
		byte[] d = new byte[length];
		for (int i = 0; i < length; i++) {
			int pos = i * 2;
			d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
		}
		return d;
	}
	
	/**
	 * Convert char to byte
	 * 2017年2月4日 xiaoming
	 * @param c
	 * @return
	 */
	private static byte charToByte(char c) {
		return (byte) "0123456789ABCDEF".indexOf(c);
	}
	
	/**
	 * 用于将zookeeper里的节点上的字节码反序列化成RSA KeyPair
	 * @param res
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws ClassNotFoundException
	 */
	public static KeyPair deserialzeKeyPair(byte[] res) throws IOException, NoSuchAlgorithmException, ClassNotFoundException
	{
		ByteArrayInputStream bi = new ByteArrayInputStream(res);
	    ObjectInputStream oi = new ObjectInputStream(bi);
	    KeyPair obj = (KeyPair) oi.readObject();
	    oi.close();
	    bi.close();
		return obj; 
	}
	
	/**
	 * 将字符串返序列化成java 对象
	 * @param classString
	 * @return
	 * @author xiaoming
	 * @throws Exception 
	 */
	public static <C> C deserialzeClass(C c, String classString) throws Exception
	{
		ByteArrayInputStream bi = new ByteArrayInputStream(Base64Utils.decode(classString));
	    ObjectInputStream oi = new ObjectInputStream(bi);
	    C obj = (C)oi.readObject();
	    oi.close();
	    bi.close();
		return obj;
	}
	
	/**
	 * 将java 对象序列表成字节
	 * @param c
	 * @return
	 * @author xiaoming
	 * @throws Exception 
	 */
	public static <C> String serialzeClass(C c) throws Exception
	{
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutputStream o = new ObjectOutputStream(b);
		o.writeObject(c);
		byte[] res = b.toByteArray();
		o.close();
		b.close();
		//简单加密处理	
		return Base64Utils.encode(res);
	}
	
	/**
	 * 用于将RSA 1024bit keypair序列号到zookeeper节点上存储
	 * @param keyPair
	 * @return  序列号字节码
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] serialzeKeyPair(KeyPair keyPair) throws IOException, NoSuchAlgorithmException
	{
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutputStream o = new ObjectOutputStream(b);
		o.writeObject(keyPair);
		byte[] res = b.toByteArray();
		o.close();
		b.close();
		//简单加密处理	
		return res;
	}
    
//	public static void main(String[] args) throws Exception {
//		
//		KeyPair key = generateKeyPair();
//		System.out.println("Private="+Base64Utils.encode(key.getPrivate().getEncoded()));
//		System.out.println("Public="+Base64Utils.encode(key.getPublic().getEncoded()));
//	}
}
