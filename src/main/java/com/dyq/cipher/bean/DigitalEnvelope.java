package com.dyq.cipher.bean;

import java.io.Serializable;

/**
 * 数字信封的封装类
 * 
 * @author dyq 20170523 1、摘要签名；2、信息密文；3、密钥密文；
 */

public class DigitalEnvelope implements Serializable {

	private static final long serialVersionUID = 1L;

	String txID; // 1、交易ID
	String messageDigestSignature; // 2、摘要签名
	String messageCipherText; // 3、信息密文
	String passwordCipherText; // 4、密钥密文
	String queueTemStr;//5、mq队列对象字符串
	String tranSubmitTime;//6、交易提交时间

	public String getTxID() {
		return txID;
	}

	public void setTxID(String txID) {
		this.txID = txID;
	}

	public String getMessageDigestSignature() {
		return messageDigestSignature;
	}

	public void setMessageDigestSignature(String messageDigestSignature) {
		this.messageDigestSignature = messageDigestSignature;
	}

	public String getMessageCipherText() {
		return messageCipherText;
	}

	public void setMessageCipherText(String messageCipherText) {
		this.messageCipherText = messageCipherText;
	}

	public String getPasswordCipherText() {
		return passwordCipherText;
	}

	public void setPasswordCipherText(String passwordCipherText) {
		this.passwordCipherText = passwordCipherText;
	}

	public String getQueueTemStr() {
		return queueTemStr;
	}

	public void setQueueTemStr(String queueTemStr) {
		this.queueTemStr = queueTemStr;
	}

	public String getTranSubmitTime() {
		return tranSubmitTime;
	}

	public void setTranSubmitTime(String tranSubmitTime) {
		this.tranSubmitTime = tranSubmitTime;
	}
	

}
