package com.dyq.cipher;

/**
 * 加密/解密、签名/验签的抽象类
 * @author dyq
 * @date 2017年4月21日
 */
public abstract class AbstractCipherService implements CipherService {

	@Override
	public abstract String messageDigest(String plainText);

	@Override
	public abstract String generateKeyPairAndGetPublicKey() throws Exception ;

	@Override
	public abstract String getPrivateKey() throws Exception ;

	@Override
	public abstract String encryptByPublicKey(String publicKey, String data) throws Exception ;

	@Override
	public abstract String decryptByPrivateKey(String privateKey, String cipherText) throws Exception ;

	@Override
	public abstract String signByPrivateKey(String privateKey, String data) throws Exception ;

	@Override
	public abstract boolean verifySignByPublicKey(String publicKey, String signText, String data) throws Exception ;

}
