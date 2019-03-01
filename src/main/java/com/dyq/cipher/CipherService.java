package com.dyq.cipher;

/**
 * 加密解密接口
 * @author dyq
 * @date 2017年4月21日
 */
public interface CipherService {
	
	//进行摘要
	public String messageDigest(String plainText);

	//生成公私钥对,同时保存私钥，返回公钥
	public String generateKeyPairAndGetPublicKey() throws Exception;
	
	//返回私钥
	public String getPrivateKey() throws Exception;
	
	//公钥加密
	public String encryptByPublicKey(String publicKey, String data) throws Exception;
	
	//私钥解密
	public String decryptByPrivateKey(String privateKey, String cipherText) throws Exception;
	
	//私钥签名
	public String signByPrivateKey(String privateKey, String data) throws Exception;
	
	//公钥验签
	public boolean verifySignByPublicKey(String publicKey, String signText, String data) throws Exception;
	
	//创建私钥的keystore文件
	public boolean createKeyStore(String storeName, String storePass, String alias);
	
	//从公钥证书中获取公钥
	public String getPublicKeyByCert(String storeName, String alias);
	
	//从公钥证书字符串中获取公钥
	public String getPublicKeyByCertString(String certString, String alias);
	
	//读取密钥库获取公钥
	public String getPublicKeyByKeyStore(String storeName, String storePass, String alias);
	
	//从keystore文件中获取私钥
	public String getPrivateKey(String storeName, String storePass, String alias);
	
	//对称加密算法， 只能加密Base64Utils 字符串
	public String encrypt(String data, String passwd);
	
	//对称解密算法，只能解密Base64Utils 字符串
	public String decrypt(String encryptedData, String passwd);
	
	//生成对称加解密的随机密钥，AES算法是UUID，SM4算法是16位字符串
	public String getRandomPassword();
	
	//将证书序列化成字符串
	public String getCertToString(String storeName, String alias);
}
