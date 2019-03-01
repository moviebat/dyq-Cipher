package com.dyq.cipher;

import com.dyq.cipher.sm.Util;
import org.junit.Before;
import org.junit.Test;

public class CipherTest {
	private Cipher cipher ;
	@Before
	public void setUp() throws Exception {
//		cipher = new Cipher("RsaCipherServiceImpl");
		Cipher cipher = Cipher.getInstanceByParm("SmCipherServiceImpl");
	}

	@Test
	public void testGenerateKeyPairAndGetPublicKey() throws Exception {
		String publicKey = cipher.generateKeyPairAndGetPublicKey();
		System.out.println(publicKey);
	}

	@Test
	public void testGetPrivateKey() throws Exception {
		String publicKey = cipher.generateKeyPairAndGetPublicKey();
		String privateKey = cipher.getPrivateKey();
		System.out.println(publicKey);
		System.out.println(privateKey);
	}

	@Test
	public void testEncryptByPublicKey() throws Exception {
		String publicKey = cipher.generateKeyPairAndGetPublicKey();
		System.out.println(publicKey);
		String plainText = "cipher";
		String cipherText = cipher.encryptByPublicKey(publicKey, plainText);
		System.out.println(cipherText);
	}

	@Test
	public void testDecryptByPrivateKey() throws Exception {
		String publicKey = cipher.generateKeyPairAndGetPublicKey();
		System.out.println(publicKey);
		String privateKey = cipher.getPrivateKey();
		System.out.println(privateKey);
		String plainText = "cipher";
		String cipherText = cipher.encryptByPublicKey(publicKey, plainText);
		System.out.println(cipherText);
		String decryptText = cipher.decryptByPrivateKey(privateKey, cipherText);
		System.out.println(decryptText);
	}

	@Test
	public void testSignByPrivateKey() throws Exception {
		String publicKey = cipher.generateKeyPairAndGetPublicKey();
		System.out.println(publicKey);
		String privateKey = cipher.getPrivateKey();
		System.out.println(privateKey);
		String plainText = "cipher";
		String signText = cipher.signByPrivateKey(privateKey, plainText);
		System.out.println(signText);
	}

	@Test
	public void testVerifySignByPublicKey() throws Exception {
		String publicKey = cipher.generateKeyPairAndGetPublicKey();
		System.out.println(publicKey);
		String privateKey = cipher.getPrivateKey();
		System.out.println(privateKey);
		String plainText = "cipher";
		String signText = cipher.signByPrivateKey(privateKey, plainText);
		System.out.println(signText);
		System.out.println(cipher.verifySignByPublicKey(publicKey, signText, plainText));
	}

	@Test
	public void testCreateKeyStore() {
		cipher.createKeyStore("d:/tdbcserver-sm", "12345678", "tdbcserver");
	}

	@Test
	public void testGetPublicKeyByCert() {
		String publicKey = cipher.getPublicKeyByCert("d:/dyq-sm.cert", "dyq");
		System.out.println(publicKey);
	}

	@Test
	public void testGetPrivateKeyStringStringString() {
		String privateKey = cipher.getPrivateKey("d:/dyq-sm", "12345678", "dyq");
		System.out.println(privateKey);
	}

	@Test
	public void testEncrypt() {
		String password = Util.getRandomString(16);
		System.out.println(password);
		String data = "cipher";
		String cipherText = cipher.encrypt(data, password);
		System.out.println(cipherText);
	}

	@Test
	public void testDecrypt() {
		String password = Util.getRandomString(16);
		System.out.println(password);
		String data = "cipher";
		String cipherText = cipher.encrypt(data, password);
		System.out.println(cipherText);
		String decryptText = cipher.decrypt(cipherText, password);
		System.out.println(decryptText);
	}

	@Test
	public void testGetRandomPassword(){
		String password = cipher.getRandomPassword();
		System.out.println(password);
	}
}
