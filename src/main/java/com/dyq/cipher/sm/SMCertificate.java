package com.dyq.cipher.sm;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Date;

import com.dyq.cipher.rsa.Base64Utils;

/**
 * sm 公钥证书
 * @author xiaoming
 * 2017年5月3日
 */
public class SMCertificate implements Serializable{
	private byte[] publicKey;
	private String signature;
	private Date createTime;
	private Date updataTime;
	private String author;
	private String summary;
	
	public SMCertificate(byte[] publicKey, byte[] privateKey, String smStorPath){
		createSMCert(publicKey, privateKey, smStorPath);
	}
	/**
	 * 创建证书实例
	 * @return
	 * @author xiaoming
	 */
	private SMCertificate createSMCert(byte[] publicKey, byte[] privateKey, String smStorPath){
		/* init cert */
		this.publicKey = publicKey;
		setCreateTime();
		this.updataTime = new Date();
		this.author = "sm";
		
		/* init summary */
		intiSummary();
		
		try {
			/* sign cert */
			this.signature = Base64Utils.encode(SM2Utils.sign("user".getBytes("ISO-8859-1"), privateKey, this.summary.getBytes("ISO-8859-1")));
			
			/* save cert file */
			if(smStorPath != null){
				FileOutputStream fos = new FileOutputStream(smStorPath, true);
				ObjectOutputStream oos = new ObjectOutputStream(fos);
				oos.writeObject(this);
				oos.flush();
				oos.close();
				fos.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return this;
	}
	
	/**
	 * 加载证书文件
	 * @param smCertPath
	 * @return
	 * @author xiaoming
	 */
	public static SMCertificate load(String smCertPath){
		try {
			FileInputStream fis = new FileInputStream(smCertPath);
			ObjectInputStream ois = new ObjectInputStream(fis);
			SMCertificate cert = (SMCertificate) ois.readObject();
			fis.close();
			ois.close();
			return cert;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * 初始化摘要信息
	 * @author xiaoming
	 */
	private void intiSummary() {
		String text = "";
		try {
			text = Base64Utils.encode(this.publicKey) + this.createTime.getTime() + this.updataTime.getTime() + this.author;
		} catch (Exception e) {
			e.printStackTrace();
		}
		this.summary = SM3Digest.hash(text);
	}
	public String getSignature() {
		return signature;
	}

	public Date getCreateTime() {
		return createTime;
	}

	private void setCreateTime() {
		this.createTime = new Date();
	}

	public Date getUpdataTime() {
		return updataTime;
	}

	public void setUpdataTime(Date updataTime) {
		this.updataTime = updataTime;
	}

	public String getAuthor() {
		return author;
	}

	public String getSummary() {
		return summary;
	}

	public byte[] getPublicKey(){
		return this.publicKey ;
	}

}
