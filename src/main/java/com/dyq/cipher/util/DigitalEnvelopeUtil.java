package com.dyq.cipher.util;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson.JSONObject;
import com.dyq.cipher.Cipher;
import com.dyq.cipher.bean.TianDeJSONObject;
import com.dyq.cipher.rsa.AESUtil;
/**
 * 数字信封
 * @author xiaoming
 */
//@Slf4j
public class DigitalEnvelopeUtil {
	
	private static final Logger log = LoggerFactory.getLogger("DigitalEnvelopeUtil");
	
	/**
	 * 封信封
	 * @param cipherMode 加密模式
	 * @param data 数字信息,明文
	 * @param publicKey 目的地公钥
	 * @return
	 */
	public static String sealEnvelope(String cipherMode, String data, String publicKey){
		/* 随机密码 */
		String passTem = UUID.randomUUID().toString();
		
		/* 拼接消息实体 */
		TianDeJSONObject json = new TianDeJSONObject();
		json.put("data", AESUtil.encryptByUTF8(data, passTem));//实际数字信息,使用密码加密后的信息
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstanceByParm(cipherMode);
			json.put("pass", cipher.encryptByPublicKey(publicKey, passTem));//信封解密密码,使用目标节点公钥加密后的密码
		} catch (Exception e) {
			json.put("pass", passTem);//信封解密密码,明文.防止  加密密码出现异常造成系统卡顿.
			e.printStackTrace();
		}		
		return json.toJSONString();
	}

	/**
	 * 拆信封
	 * @param data 密文数字信息
	 * @param privateKey 本节点私钥,用于解密aes密码
	 * @return
	 */
    public static String removeEnvelope(String cipherMode, String envelope, String privateKey){
		/* 解密得到密码 */
    	JSONObject envelopeJson = JSONObject.parseObject(envelope);
    	String pass = null;
    	Cipher cipher = null;
    	try {
    		cipher = Cipher.getInstanceByParm(cipherMode);
    		pass = cipher.decryptByPrivateKey(privateKey, envelopeJson.getString("pass"));
		} catch (Exception e) {
			pass = envelopeJson.getString("pass");//如果出现异常可能密码是明文
			e.printStackTrace();
		}
    	
    	/* 解密获取 真正的数字信息 */
    	String data = AESUtil.decryptByUTF8(envelopeJson.getString("data"), pass);
    	
		return data;
	}
}
