package com.dyq.cipher.sm;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Date;

import com.dyq.cipher.rsa.Base64Utils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * sm密钥库
 * @author xiaoming
 * 2017年5月3日
 */
//@Slf4j
public class SMKeyStore implements Serializable{
	private byte[] privateKey;
	private String signature;
	private Date createTime;
	private Date updataTime;
	private String author;
	private String summary;
	private SMCertificate cert;
	
	private static final Logger log = LoggerFactory.getLogger("SMKeyStore");
	
	public SMKeyStore(String smKeyStorePath, String smKeyStorPass){
		createSMKeyStore(smKeyStorePath, smKeyStorPass);
	}
	/**
	 * 创建sm 密钥库
	 * @param smKeyStorePath
	 * @param smKeyStorPass
	 * @author xiaoming
	 */
	private void createSMKeyStore(String smKeyStorePath, String smKeyStorPass){
		AsymmetricCipherKeyPair kp = SM2Utils.generateKeyPair();
		
		/* init keystor */
		try {
			savePrivateKey(smKeyStorPass, kp);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Date date = new Date();
		this.createTime = date;
		this.updataTime = date;
		this.author = "sm2";
		
		/* init cert */
		createCert(kp, smKeyStorePath);
		
		/* init summary */
		intiSummary();
		
		try {
			/* sign cert */
			this.signature = Base64Utils.encode(SM2Utils.sign("user".getBytes("ISO-8859-1"),
					Util.byteConvert32Bytes(((ECPrivateKeyParameters) kp.getPrivate()).getD()), 
					this.summary.getBytes("ISO-8859-1")));
			
			/* save cert file */
			FileOutputStream fos = new FileOutputStream(smKeyStorePath, true);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(this);
			oos.flush();
			oos.close();
			fos.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	/**
	 * 加载smkeystore
	 * @param smKeyStorePath
	 * @param smKeyStorPass
	 * @return SMKeyStore
	 * @author xiaoming
	 */
	public static SMKeyStore load(String smKeyStorePath, String smKeyStorPass){
		try {
			FileInputStream fis = new FileInputStream(smKeyStorePath);
			ObjectInputStream ois = new ObjectInputStream(fis);
			SMKeyStore smKeyStore = (SMKeyStore) ois.readObject();
			fis.close();
			ois.close();
			
			/* 解密私钥  */
			SM4Utils sm4 = new SM4Utils();
			sm4.setSecretKey(smKeyStorPass);
			String privateKeyStr = sm4.decryptData_ECB(Base64Utils.encode(smKeyStore.getPrivateKey()));
			smKeyStore.setPrivateKey(Base64Utils.decode(privateKeyStr));
			return smKeyStore;
		} catch (Exception e) {
			log.error("Store file is not exist.");
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * 创建私钥对应的公钥证书
	 * @param kp
	 * @author xiaoming
	 */
	private void createCert(AsymmetricCipherKeyPair kp, String smKeyStorePath) {
		SMCertificate cert = new SMCertificate(((ECPublicKeyParameters) kp.getPublic()).getQ().getEncoded(), 
				Util.byteConvert32Bytes(((ECPrivateKeyParameters) kp.getPrivate()).getD()),
				smKeyStorePath + ".cert");
		this.cert = cert;
	}
	/**
	 * sm4加密密钥    dyq 20170518 将密码长度修改为大于等于6，16太长
	 * @param smKeyStorPass
	 * @author xiaoming
	 * @throws Exception 
	 */
	private void savePrivateKey(String smKeyStorPass, AsymmetricCipherKeyPair kp) throws Exception {
		if(smKeyStorPass == null || (smKeyStorPass.length() < 6)){
			throw new Exception("key is null or length less than 6");
		}
		SM4Utils sm4 = new SM4Utils();
		sm4.setSecretKey(smKeyStorPass);
		this.privateKey = Base64Utils.decode(sm4.encryptData_ECB(Base64Utils.encode(Util.byteConvert32Bytes(((ECPrivateKeyParameters) kp.getPrivate()).getD()))));
	}
	/**
	 * 初始化摘要信息
	 * @author xiaoming
	 */
	private void intiSummary() {
		String text = "";
		try {
			text = Base64Utils.encode(this.privateKey) + this.createTime.getTime() + this.updataTime.getTime() + this.author;
		} catch (Exception e) {
			e.printStackTrace();
		}
		this.summary = SM3Digest.hash(text);
	}
	/**
	 * 验证证书
	 * @param cert
	 * @return
	 * @author xiaoming
	 */
	public boolean verifyCert(SMCertificate cert){
		try {
			String text = Base64Utils.encode(cert.getPublicKey()) + cert.getCreateTime().getTime() + cert.getUpdataTime().getTime() + cert.getAuthor();
			String summary = SM3Digest.hash(text);
			return SM2Utils.verifySign("user".getBytes("ISO-8859-1"), getPublicKey(), summary.getBytes("ISO-8859-1"), Base64Utils.decode(cert.getSignature()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	
	public byte[] getPrivateKey() {
		return privateKey;
	}
	public byte[] setPrivateKey(byte[]  privateKey) {
		return this.privateKey = privateKey;
	}
	public String getSignature() {
		return signature;
	}
	public Date getCreateTime() {
		return createTime;
	}
	public Date getUpdataTime() {
		return updataTime;
	}
	public String getAuthor() {
		return author;
	}
	public String getSummary() {
		return summary;
	}
	public SMCertificate getCert() {
		return cert;
	}
	/**
	 * 获取公钥
	 * @return
	 * @author xiaoming
	 */
	public byte[] getPublicKey(){
		return this.cert.getPublicKey();
	}	
}
