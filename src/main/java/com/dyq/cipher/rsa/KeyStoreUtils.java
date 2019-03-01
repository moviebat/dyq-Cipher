package com.dyq.cipher.rsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//@Slf4j
public class KeyStoreUtils{
	/**
	 * Java密钥库(Java Key Store，JKS)KEY_STORE
	 */
	public static final String KEY_STORE = "JKS";

	public static final String X509 = "X.509";
	
	private static final Logger log = LoggerFactory.getLogger("KeyStoreUtils");

	/**
	 * 获得KeyStore
	 * 
	 * @author    liwh
	 * @version   2017-4-1
	 * @param keyStorePath
	 * @param password
	 * @return
	 * @throws Exception
	 */
	private static KeyStore getKeyStore(String keyStorePath, String password)
			throws Exception {
		FileInputStream is = null;
		KeyStore ks = null;
		try{
			is = new FileInputStream(keyStorePath);			
			ks = KeyStore.getInstance(KEY_STORE);
			ks.load(is, password.toCharArray());			
		}catch(FileNotFoundException e){
			log.error("The store file:{} is not exist.",keyStorePath);
			e.printStackTrace();
		}finally{
			if(null!=is){
				is.close();	
			}			
		}
		return ks;
	}

	/**
	 * 由KeyStore获得私钥
	 * @author    liwh
	 * @param keyStorePath
	 * @param alias
	 * @param storePass
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey getPrivateKey(String keyStorePath, String alias, String storePass, String keyPass) throws Exception {
		KeyStore ks = getKeyStore(keyStorePath, storePass);
		PrivateKey key = (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
		return key;
	}
	
	/**
	 * 由Certificate获得公钥
	 * @author    liwh
	 * @param keyStorePath
	 *            KeyStore路径
	 * @param alias
	 *            别名
	 * @param storePass
	 *            KeyStore访问密码
	 * @return
	 * @throws Exception
	 */
	public static PublicKey getPublicKey(String keyStorePath, String alias, String storePass) throws Exception {
		KeyStore ks = getKeyStore(keyStorePath, storePass);
		PublicKey key = ks.getCertificate(alias).getPublicKey();
		return key;
	}
	   
	   /**
	    * 从KeyStore中获取公钥，并经BASE64编码
        * @author    liwh
	     * @param keyStorePath
	    * @param alias
	    * @param storePass
	    * @return
	    * @throws Exception
	    */
	   public static String getStrPublicKey(String keyStorePath, String alias,String storePass) throws Exception{
		   PublicKey key = getPublicKey(keyStorePath, alias, storePass);
		   String strKey = Base64Utils.encode(key.getEncoded());		   
		   return strKey;
	   }
	   
	   /**
	    * 获取经BASE64编码后的私钥
        * @author    liwh
	    * @param keyStorePath
	    * @param alias
	    * @param storePass
	    * @param keyPass
	    * @return
	    * @throws Exception
	    */
	   public static String getStrPrivateKey(String keyStorePath, String alias,String storePass, String keyPass) throws Exception{

		   PrivateKey key = getPrivateKey(keyStorePath, alias, storePass, keyPass);
		   String strKey = Base64Utils.encode(key.getEncoded());
		   return strKey;
	   }
	
	/**
	 * 使用公钥加密数据
     * @author    liwh
	 * @param publicKey
	 * @param srcData
	 * @return
	 * @throws Exception
	 */
	public static String encryptByPublicKey(String publicKey, String srcData) throws Exception{
		//解密
		byte[] pk = Base64Utils.decode(publicKey);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(pk);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		//获取公钥
		PublicKey pubKey = kf.generatePublic(spec);
		
		// 对数据加密
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		
		byte[] doFinal = cipher.doFinal(srcData.getBytes());
		return Base64Utils.encode(doFinal);
	}
	
	
	/**
	 * 使用私钥解密数据
     * @author    liwh
	 * @param privateKey
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String descryptByPrivateKey(String privateKey, String data) throws Exception{
		// BASE64转码解密私钥
		byte[] pk = Base64Utils.decode(privateKey);
		// BASE64转码解密密文
		byte[] text =  Base64Utils.decode(data);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pk);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		// 获取私钥
		PrivateKey prvKey = kf.generatePrivate(spec);
		
		// 对数据加密
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, prvKey);
		
		byte[] doFinal = cipher.doFinal(text);
		return new String(doFinal);
	}
	
	/**
     * 生成keyStore
     * @param keystroePath
     * @param alias
     * @param pass 密码必须长度6以上
     * @author xiaoming
     */
	public static void genkeyStore(String keystroePath, String alias, String pass) {
		if(pass.length() < 6){
			throw new RuntimeException("pass length is less 6");
		}
		String[] arstringCommand = new String[] { "keytool", "-genkey", // -genkey表示生成密钥
				"-validity", // -validity指定证书有效期(单位：天)，这里是36000天
				"36500", "-keysize", // 指定密钥长度
				"1024", "-alias", // -alias指定别名，这里是ss
				alias, "-keyalg", // -keyalg 指定密钥的算法 (如 RSA DSA（如果不指定默认采用DSA）)
				"RSA", "-keystore", // -keystore指定存储位置，这里是d:/demo.keystore
				keystroePath, "-dname", // CN=(名字与姓氏), OU=(组织单位名称), O=(组织名称),
										// L=(城市或区域名称),
										// ST=(州或省份名称), C=(单位的两字母国家代码)"
				"CN=(" + alias + "), OU=(" + alias + "), O=(" + alias + "), L=(BJ), ST=(BJ), C=(CN)", "-storepass", // 指定密钥库的密码(获取keystore信息所需的密码)
				pass, "-keypass", // 指定别名条目的密码(私钥的密码)
				pass, "-v"// -v 显示密钥库中的证书详细信息
		};
		execCommand(arstringCommand);
		//生成证书
		genCert(keystroePath, alias, pass);
	}
	/**
	 * 生成证书
	 * @param keystroePath
	 * @param alias
	 * @param pass
	 * @author xiaoming
	 */
	public static void genCert(String keystroePath, String alias, String pass){
		String[] arstringCommand = new String[] {"keytool","-export",
				"-alias", alias, 
				"-keystore", keystroePath,
				"-file",  keystroePath + ".cert",
				"-storepass", pass};
		
		//等待.ks文件生成完成
		File f = new File(keystroePath);
		while(!f.exists()){
			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {e.printStackTrace();}
		}
		execCommand(arstringCommand);
	}
	
	/**
     * 调用cmd
     * @param arstringCommand
     * @author xiaoming
     */
	public static void execCommand(String[] arstringCommand) {
		try {
			Runtime.getRuntime().exec(arstringCommand);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 读取证书获取公钥
	 * @param path  证书路径
	 * @return
	 * @throws Exception
	 * @author xiaoming
	 */
	public static String getPublicKeyForCert(String path) throws Exception {
		CertificateFactory certificate_factory = CertificateFactory.getInstance(X509);
		FileInputStream file_inputstream = new FileInputStream(path);
		X509Certificate x509certificate = (X509Certificate) certificate_factory.generateCertificate(file_inputstream);
		file_inputstream.close();
		return Base64Utils.encode(x509certificate.getPublicKey().getEncoded());
	}
	
	public static String getPass(String storePass){
    	/* 密码固定 长度=16 */
		if(storePass.length() < 16){
			char[] pass = new char[16];
			char[] pass_old = storePass.toCharArray();
			int i = 0;
			for(;i < pass_old.length;i++){
				pass[i] = pass_old[i];
			}
			//不全密码
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
