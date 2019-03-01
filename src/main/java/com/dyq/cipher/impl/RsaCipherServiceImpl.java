package com.dyq.cipher.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.dyq.cipher.AbstractCipherService;
import com.dyq.cipher.rsa.AESUtil;
import com.dyq.cipher.rsa.Base64Utils;
import com.dyq.cipher.rsa.KeyStoreUtils;
import com.dyq.cipher.rsa.RSAUtils;
import com.dyq.cipher.rsa.SHA256Util;


/**
 * 商密rsa的加密/解密、签名/验签、摘要实现类
 * @author dyq
 * @date 2017年4月21日
 */
//@Slf4j
public class RsaCipherServiceImpl extends AbstractCipherService {
	/* 保存私钥字符串 */
	private static String privateKey = "";
	
	public static final String X509 = "X.509";
	
	private static final Logger log = LoggerFactory.getLogger("RsaCipherServiceImpl");
	
	private static Map<String, PublicKey> publicKeyCacher = new HashMap<String, PublicKey>();
	private static Map<String, PrivateKey> privateKeyCacher = new HashMap<String, PrivateKey>();
	
	@Override
	public String messageDigest(String plainText) {
		String hash = SHA256Util.hash(plainText.toString());
		return hash;
	}

	@Override
	public String generateKeyPairAndGetPublicKey() throws Exception {
		KeyPair kp = RSAUtils.generateKeyPair();
		RSAPrivateKey privateK = (RSAPrivateKey)kp.getPrivate(); 
		RSAPublicKey publicK = (RSAPublicKey)kp.getPublic();
		/* 保存私钥 */
		privateKey = Base64Utils.encode(privateK.getEncoded());
		
		/* 返回公钥 */
		return Base64Utils.encode(publicK.getEncoded());
	}

	@Override
	public String getPrivateKey() throws Exception {
		return privateKey;
	}

	@Override
	public String encryptByPublicKey(String publicKey, String data) throws Exception {
		PublicKey p = publicKeyCacher.get(publicKey);
		if(p == null){
			p = RSAUtils.getPublicKey(publicKey);
			publicKeyCacher.put(publicKey, p);
		}
		String cipherText = RSAUtils.encryptByString(data, p);
		return cipherText;
	}

	@Override
	public String decryptByPrivateKey(String privateKey, String cipherText) throws Exception {
		PrivateKey p = privateKeyCacher.get(privateKey);
		if(p == null){
			p = RSAUtils.getPrivateKey(privateKey);
			privateKeyCacher.put(privateKey, p);
		}
		String plainText = RSAUtils.decryptToString(cipherText, p);
		return plainText;
		
	}

	@Override
	public String signByPrivateKey(String privateKey, String data) throws Exception {
		PrivateKey p = privateKeyCacher.get(privateKey);
		if(p == null){
			p = RSAUtils.getPrivateKey(privateKey);
			privateKeyCacher.put(privateKey, p);
		}
		String	signText = RSAUtils.signName(data, p);

		return signText;
		
	}

	@Override
	public boolean verifySignByPublicKey(String publicKey, String signText, String data) throws Exception {
		boolean verifySign = false;
		PublicKey p = publicKeyCacher.get(publicKey);
		if(p == null){
			p = RSAUtils.getPublicKey(publicKey);
			publicKeyCacher.put(publicKey, p);
		}
		verifySign = RSAUtils.verify(signText, data, p);
		return verifySign;
		
	}

	@Override
	public boolean createKeyStore(String storeName, String storePass, String alias) {
		/* 密码固定 长度=16 */
		storePass = KeyStoreUtils.getPass(storePass);		
		/* 生成密key strore  同时生成公钥证书文件  */
		KeyStoreUtils.genkeyStore(storeName, alias, storePass);
		KeyStoreUtils.genCert(storeName, alias, storePass);
		File f = new File(storeName + ".cert");
		while(!f.exists()){
			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {
				log.error("Cannot create privateKey store file.");
				e.printStackTrace();
			}
		}
		return true;
	}

	@Override
	public String getPublicKeyByCert(String storeName, String alias) {
		String publicKey = null;
		try {
			publicKey = KeyStoreUtils.getPublicKeyForCert(storeName);
		} catch (Exception e) {
			log.error("Cannot load publicKey Cert file or the file is destroyed.");
			e.printStackTrace();
		}		
		return publicKey;
	}

	@Override
	public String getPublicKeyByCertString(String certString, String alias) {
		String publicKey = null;
		try {
			X509Certificate x509certificate  =  RSAUtils.deserialzeClass(null, certString);
			publicKey = Base64Utils.encode(x509certificate.getPublicKey().getEncoded());
		} catch (Exception e) {
			log.error("Cannot load publicKey Cert file or the file is destroyed.");
			e.printStackTrace();
		}
		return publicKey;
	}

	@Override
	public String getPublicKeyByKeyStore(String storeName, String storePass, String alias) {
    	/* 密码固定 长度=16 */
		storePass = KeyStoreUtils.getPass(storePass);
		String publicKey = null;
		try {
			PublicKey key = KeyStoreUtils.getPublicKey(storeName, alias, storePass);
			publicKey = Base64Utils.encode(key.getEncoded());
		} catch (Exception e) {
			log.error("Cannot load publicKey Cert file or the file is destroyed.");
			e.printStackTrace();
		}		
		return publicKey;
	}
	
	@Override
	public String getPrivateKey(String storeName, String storePass, String alias) {
    	/* 密码固定 长度=16 */
		storePass = KeyStoreUtils.getPass(storePass);
		String privateKey = null;
		try {
			PrivateKey priKey = KeyStoreUtils.getPrivateKey(storeName, alias, storePass, storePass);
			privateKey = Base64Utils.encode(priKey.getEncoded());
		} catch (Exception e) {
			log.error("Cannot load privateKey store file or the file is destroyed.");
			e.printStackTrace();
		}		
		return privateKey;
	}

	@Override
	public String encrypt(String data, String passwd) {
		return AESUtil.encrypt(data, passwd);
	}

	@Override
	public String decrypt(String encryptedData, String passwd) {
		return AESUtil.decrypt(encryptedData,passwd);
	}

	@Override
	public String getRandomPassword() {
		String aesPassword = UUID.randomUUID().toString();//aes随机密码
		return aesPassword;
	}

	@Override
	public String getCertToString(String storeName, String alias) {
		X509Certificate x509certificate = null;
		FileInputStream file_inputstream = null;
		try {
			CertificateFactory certificate_factory = CertificateFactory.getInstance(X509);
			file_inputstream = new FileInputStream(storeName);
			x509certificate = (X509Certificate) certificate_factory.generateCertificate(file_inputstream);
			return RSAUtils.serialzeClass(x509certificate);
		} catch (Exception e) {
			e.printStackTrace();
		}finally{
			if(null!=file_inputstream){
				try{
					file_inputstream.close();
				}catch(IOException e){
					e.printStackTrace();
				}
			}
		}
		return null;
	}
}
