package com.dyq.cipher.impl;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.dyq.cipher.AbstractCipherService;
import com.dyq.cipher.rsa.Base64Utils;
import com.dyq.cipher.rsa.KeyStoreUtils;
import com.dyq.cipher.rsa.RSAUtils;
import com.dyq.cipher.sm.SM2Utils;
import com.dyq.cipher.sm.SM3Digest;
import com.dyq.cipher.sm.SM4Utils;
import com.dyq.cipher.sm.SMCertificate;
import com.dyq.cipher.sm.SMKeyStore;
import com.dyq.cipher.sm.Util;

//import lombok.extern.slf4j.Slf4j;
/**
 * 国密sm的加密/解密、签名/验签、摘要实现类
 * @author dyq
 * @date 2017年4月21日
 */
//@Slf4j
public class SmCipherServiceImpl extends AbstractCipherService {
	/* 保存私钥字符串 */
	private static String privateKey = "";
	private static final Logger log = LoggerFactory.getLogger("SmCipherServiceImpl");
	
	private static Map<String, PublicKey> publicKeyCacher = new HashMap<String, PublicKey>();
	private static Map<String, PrivateKey> privateKeyCacher = new HashMap<String, PrivateKey>();
	
	@Override
	public String messageDigest(String plainText) {
		String hash = SM3Digest.hash(plainText);
		return hash;
	}

	@Override
	public String generateKeyPairAndGetPublicKey() throws Exception {
		AsymmetricCipherKeyPair kp = SM2Utils.generateKeyPair();
		/* 保存私钥 */
		privateKey = Base64Utils.encode(Util.byteConvert32Bytes(((ECPrivateKeyParameters) kp.getPrivate()).getD()));
		
		/* 返回公钥 */
		return Base64Utils.encode(((ECPublicKeyParameters) kp.getPublic()).getQ().getEncoded());
	}

	@Override
	public String getPrivateKey() throws Exception {
		return privateKey;
	}

	@Override
	public String encryptByPublicKey(String publicKey, String data) throws Exception {
		String cipherText = Base64Utils.encode(SM2Utils.encrypt(Base64Utils.decode(publicKey), data.getBytes("ISO-8859-1")));
		return cipherText;
	}

	@Override
	public String decryptByPrivateKey(String privateKey, String cipherText) throws Exception {
		String plainText = new String(SM2Utils.decrypt(Base64Utils.decode(privateKey), Base64Utils.decode(cipherText)), "ISO-8859-1");
	    return plainText;
	}

	@Override
	public String signByPrivateKey(String privateKey, String data) throws Exception {
		String signText = Base64Utils.encode(SM2Utils.sign("user".getBytes("ISO-8859-1"), Base64Utils.decode(privateKey), data.getBytes("ISO-8859-1")));
		return signText;
	}

	@Override
	public boolean verifySignByPublicKey(String publicKey, String signText, String data) throws Exception {
		boolean verifySign = false;
		verifySign = SM2Utils.verifySign("user".getBytes("ISO-8859-1"), Base64Utils.decode(publicKey), data.getBytes("ISO-8859-1"), Base64Utils.decode(signText));
		return verifySign;
	}

	@Override
	public boolean createKeyStore(String storeName, String storePass, String alias) {
		/* 密码固定 长度=16 */
		storePass = KeyStoreUtils.getPass(storePass);		
		/* 生成密key strore  同时生成公钥证书文件  */
		new SMKeyStore(storeName , storePass);
		return true;
	}

	@Override
	public String getPublicKeyByCert(String storeName, String alias) {
		String publicKey = null;		
		try {
			SMCertificate cert = SMCertificate.load(storeName);
			publicKey = Base64Utils.encode(cert.getPublicKey());
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
			SMCertificate cert = RSAUtils.deserialzeClass(null, certString);
			publicKey = Base64Utils.encode(cert.getPublicKey());
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
			SMKeyStore store =  SMKeyStore.load(storeName , storePass);
			publicKey = Base64Utils.encode(store.getPublicKey());
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
			SMKeyStore store =  SMKeyStore.load(storeName, storePass);
			privateKey = Base64Utils.encode(store.getPrivateKey());
		} catch (Exception e) {
			log.error("Cannot load privateKey store file or the file is destroyed.");
			e.printStackTrace();
		}	
		return privateKey;
	}

	@Override
	public String encrypt(String data, String passwd) {
		SM4Utils sm4 = new SM4Utils();
		sm4.setSecretKey(passwd);
		return sm4.encryptData_ECB(data);
	}

	@Override
	public String decrypt(String encryptedData, String passwd) {
		SM4Utils sm4 = new SM4Utils();
		sm4.setSecretKey(passwd);
		return sm4.decryptData_ECB(encryptedData);
	}

	@Override
	public String getRandomPassword() {
		String password = Util.getRandomString(16);
		return password;
	}

	@Override
	public String getCertToString(String storeName, String alias) {
		SMCertificate cert = SMCertificate.load(storeName);
		try {
			return RSAUtils.serialzeClass(cert);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
