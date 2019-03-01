package com.dyq.cipher.rsa;

import java.io.File;
import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.dyq.cipher.sm.SMCertificate;
import com.dyq.cipher.sm.SMKeyStore;



/**
 * 区块链 密钥库工具类
 * @author xiaoming
 * 2017年5月4日
 */
public class BCKeyStoreUtil {
	private static String  ENCRYPTION_TYPE = "RSA";
	private static String rootPath = System.getProperty("user.dir");
	public static final String X509 = "X.509";
	
	/**
	 * 创建密钥库
	 * @param storeName
	 * @param storePass
	 * @author xiaoming
	 */
	public static void createKeyStore(String storeName, String storePass, String alias){
		/* 密码固定 长度=16 */
		storePass = KeyStoreUtils.getPass(storePass);
		
		/* 生成密key strore  同时生成公钥证书文件  */
		if("RSA".equals(ENCRYPTION_TYPE)){
			String path = rootPath + File.separator + storeName + "-rsa.ks";
			KeyStoreUtils.genkeyStore(path, alias, storePass);
			KeyStoreUtils.genCert(path, alias, storePass);
			File f = new File(path + ".cert");
			while(!f.exists()){
				try {
					Thread.sleep(200);
				} catch (InterruptedException e) {e.printStackTrace();}
			}
		}else if("SM2".equals(ENCRYPTION_TYPE)){
			new SMKeyStore(rootPath + File.separator + storeName + "-sm2.ks", storePass);
		}
	}
	
	/**
	 * 读取证书获取公钥
	 * @param storeName
	 * @param alias
	 * @return
	 * @author xiaoming
	 */
	public static String getPublicKeyByCert(String storeName, String alias){
		String publicKey = null;
		if("RSA".equals(ENCRYPTION_TYPE)){
			try {
				publicKey = KeyStoreUtils.getPublicKeyForCert(storeName);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}else if("SM2".equals(ENCRYPTION_TYPE)){
			SMCertificate cert = SMCertificate.load(rootPath + File.separator + storeName + "-sm2.ks.cert");
			try {
				publicKey = Base64Utils.encode(cert.getPublicKey());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		return publicKey;
	}
	
	/**
	 * 从证书字符串中获取公钥
	 * @param certString
	 * @param alias
	 * @return
	 * @author xiaoming
	 */
	public static String getPublicKeyByCertString(String certString, String alias){
		String publicKey = null;
		if("RSA".equals(ENCRYPTION_TYPE)){
			try {
				X509Certificate x509certificate  =  RSAUtils.deserialzeClass(null, certString);
				publicKey = Base64Utils.encode(x509certificate.getPublicKey().getEncoded());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}else if("SM2".equals(ENCRYPTION_TYPE)){
			try {
				SMCertificate cert = RSAUtils.deserialzeClass(null, certString);
				publicKey = Base64Utils.encode(cert.getPublicKey());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return publicKey;
	}
	
	/**
	 * 读取密钥库获取公钥
	 * @param storeName
	 * @param storePass
	 * @param alias
	 * @return
	 * @author xiaoming
	 */
    public static String getPublicKeyByKeyStore(String storeName, String storePass, String alias){
    	/* 密码固定 长度=16 */
		storePass = KeyStoreUtils.getPass(storePass);
		String publicKey = null;
		if("RSA".equals(ENCRYPTION_TYPE)){
			try {
				PublicKey key = KeyStoreUtils.getPublicKey(rootPath + File.separator + storeName + "-rsa.ks", alias, storePass);
				publicKey = Base64Utils.encode(key.getEncoded());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}else if("SM2".equals(ENCRYPTION_TYPE)){
			SMKeyStore store =  SMKeyStore.load(rootPath + File.separator + storeName + "-sm2.ks", storePass);
			try {
				publicKey = Base64Utils.encode(store.getPublicKey());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		return publicKey;
	}
    
    public static String getPrivateKey(String storeName, String storePass, String alias){
    	/* 密码固定 长度=16 */
		storePass = KeyStoreUtils.getPass(storePass);
		String privateKey = null;
		if("RSA".equals(ENCRYPTION_TYPE)){
			try {
				PrivateKey priKey = KeyStoreUtils.getPrivateKey(storeName, alias, storePass, storePass);
				privateKey = Base64Utils.encode(priKey.getEncoded());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}else if("SM2".equals(ENCRYPTION_TYPE)){
			SMKeyStore store =  SMKeyStore.load(rootPath + File.separator +storeName + "-sm2.ks", storePass);
			try {
				privateKey = Base64Utils.encode(store.getPrivateKey());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		return privateKey;
    }
	

    /**
     * 将证书序列化成字符串
     * @param storeName
     * @param alias
     * @return
     * @author xiaoming
     */
    public static String getCertToString(String storeName, String alias){
    	if("RSA".equals(ENCRYPTION_TYPE)){
			try {
				CertificateFactory certificate_factory = CertificateFactory.getInstance(X509);
				FileInputStream file_inputstream = new FileInputStream(rootPath + File.separator + storeName + "-rsa.ks.cert");
				X509Certificate x509certificate = (X509Certificate) certificate_factory.generateCertificate(file_inputstream);
				file_inputstream.close();
				return RSAUtils.serialzeClass(x509certificate);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}else if("SM2".equals(ENCRYPTION_TYPE)){
			SMCertificate cert = SMCertificate.load(rootPath + File.separator + storeName + "-sm2.ks.cert");
			try {
				return RSAUtils.serialzeClass(cert);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
    	return null;
    }

//	public static void main(String[] args) throws Exception {
//		AsymmetricEncryptionUtils.useSM2();
//		BCKeyStoreUtil.createKeyStore("bc", "123", "test");
//		
//		//加密
//		String cipherText = AsymmetricEncryptionUtils.encryptByPublicKey(BCKeyStoreUtil.getPublicKeyByCert("bc", "test"), "lmd");
//		
//		//解密
//		String text = AsymmetricEncryptionUtils.decryptByPrivateKey(BCKeyStoreUtil.getPrivateKey("bc", "123", "test"), cipherText);
//		System.out.println(text);
//		
//	}

}
