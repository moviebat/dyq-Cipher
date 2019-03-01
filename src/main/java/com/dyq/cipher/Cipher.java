package com.dyq.cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Ciper 各个组件管理调用类
 * 根据配置文件来选择  是国密还是商密
 * Created by dyq on 2017/4/20.
 */
//@Slf4j
public class Cipher {
	private static volatile Cipher instance = null;   //声明成 volatile
	private static CipherService cipherService;        //加解密服务接口
	
	private static final Logger log = LoggerFactory.getLogger("Cipher");

	//根据传入参数来选择加解密体系为国密还是RSA体系
	private Cipher(String className) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		try {
			cipherService = (CipherService)(Class.forName(className).newInstance());
		} catch (Exception e) {
			log.error("Cannot find the cipher class："+className);
			e.printStackTrace();
		}
	}
	          
	public static Cipher getInstanceByParm(String className){
    	try{
        	if (null != instance) {
        	}else{	
        	    synchronized (Cipher.class) {
        	        if (instance == null) {
        	            instance = new Cipher(className);;	    	           
        	        }
        	      }
        	}    		
    	}catch(Exception e){
    		log.error("Cannot create the cipher instance："+className);
    		e.printStackTrace();
    	}
    	return instance;
    }
    
    public String messageDigest(String plainText){
       return cipherService.messageDigest(plainText);
    }
    
    public String generateKeyPairAndGetPublicKey() throws Exception{
	   return cipherService.generateKeyPairAndGetPublicKey();
    }
    
    public String getPrivateKey() throws Exception {
	   return cipherService.getPrivateKey();
    }
    
    public String encryptByPublicKey(String publicKey, String data) throws Exception {
	   return cipherService.encryptByPublicKey(publicKey, data);
    }
   
    public String decryptByPrivateKey(String privateKey, String cipherText) throws Exception {
	   return cipherService.decryptByPrivateKey(privateKey, cipherText);
    }
    
    public String signByPrivateKey(String privateKey, String data) throws Exception {
	   return cipherService.signByPrivateKey(privateKey, data);
    }
   
    public boolean verifySignByPublicKey(String publicKey, String signText, String data) throws Exception {
    	return cipherService.verifySignByPublicKey(publicKey, signText, data);
    }
	//创建私钥的keystore文件
	public boolean createKeyStore(String storeName, String storePass, String alias){
		return cipherService.createKeyStore(storeName,storePass,alias);
	}
	
	//从公钥证书中获取公钥
	public String getPublicKeyByCert(String storeName, String alias){
		return cipherService.getPublicKeyByCert(storeName, alias);
	}
	
	//从公钥证书字符串中获取公钥
	public String getPublicKeyByCertString(String certString, String alias){
		return cipherService.getPublicKeyByCertString(certString, alias);
	}
	
	//读取密钥库获取公钥
	public String getPublicKeyByKeyStore(String storeName, String storePass, String alias){
		return cipherService.getPublicKeyByKeyStore(storeName, storePass, alias);
	}
	
	//从keystore文件中获取私钥
	public String getPrivateKey(String storeName, String storePass, String alias){
		return cipherService.getPrivateKey(storeName, storePass, alias);
	}
	
	//对称加密算法， 只能加密Base64Utils 字符串
	public String encrypt(String data, String passwd){
		return cipherService.encrypt(data, passwd);
	}
	
	//对称解密算法，只能解密Base64Utils 字符串
	public String decrypt(String encryptedData, String passwd){
		return cipherService.decrypt(encryptedData, passwd);
	}
	
	//生成对称加解密的随机密钥，AES算法是UUID，SM4算法是16位字符串
	public String getRandomPassword(){
		return cipherService.getRandomPassword();
	}
	
	//将证书序列化成字符串
	public String getCertToString(String storeName, String alias){
		return cipherService.getCertToString(storeName, alias);
	}
}
