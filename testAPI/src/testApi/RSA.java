package testApi;

import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class RSA {
	private static final byte[] PQ = { (byte) 0xC2, (byte) 0xD3, (byte) 0x23,
			(byte) 0x03, (byte) 0x62, (byte) 0x93, (byte) 0x75, (byte) 0xBF,
			(byte) 0xA8, (byte) 0xA3, (byte) 0x16, (byte) 0x5D, (byte) 0xF0,
			(byte) 0x6A, (byte) 0x58, (byte) 0x0F, (byte) 0xCA, (byte) 0xD0,
			(byte) 0x37, (byte) 0x68, (byte) 0x0A, (byte) 0x0F, (byte) 0xF2,
			(byte) 0x8A, (byte) 0x38, (byte) 0x70, (byte) 0xA1, (byte) 0xAB,
			(byte) 0x59, (byte) 0x84, (byte) 0x04, (byte) 0x5D, (byte) 0x5D,
			(byte) 0x71, (byte) 0x86, (byte) 0xCC, (byte) 0x17, (byte) 0x07,
			(byte) 0xB3, (byte) 0xC0, (byte) 0x6C, (byte) 0x8E, (byte) 0x39,
			(byte) 0xFB, (byte) 0xA8, (byte) 0xAA, (byte) 0x09, (byte) 0xB2,
			(byte) 0x02, (byte) 0x21, (byte) 0xF2, (byte) 0x4D, (byte) 0x55,
			(byte) 0x2D, (byte) 0x71, (byte) 0x3C, (byte) 0xE4, (byte) 0xE8,
			(byte) 0x61, (byte) 0x2A, (byte) 0xDE, (byte) 0x12, (byte) 0x85,
			(byte) 0x28, (byte) 0xD6, (byte) 0x39, (byte) 0xD4, (byte) 0xF4,
			(byte) 0x56, (byte) 0x22, (byte) 0xDF, (byte) 0xA9, };

	private static final byte[] DQ = { (byte) 0xA6, (byte) 0x13, (byte) 0xB0,
			(byte) 0xB1, (byte) 0x61, (byte) 0x7A, (byte) 0x2B, (byte) 0x63,
			(byte) 0x3B, (byte) 0x76, (byte) 0xA1, (byte) 0x91, (byte) 0x97,
			(byte) 0x6B, (byte) 0xF2, (byte) 0xCD, (byte) 0x7A, (byte) 0xF3,
			(byte) 0x44, (byte) 0xE2, (byte) 0x68, (byte) 0xA5, (byte) 0xD1,
			(byte) 0x25, (byte) 0xB9, (byte) 0x93, (byte) 0x4F, (byte) 0xB3,
			(byte) 0xCA, (byte) 0x9F, (byte) 0x2E, (byte) 0x45, (byte) 0x5D,
			(byte) 0x8A, (byte) 0x4C, (byte) 0xBF, (byte) 0x04, (byte) 0x78,
			(byte) 0x21, (byte) 0x95, (byte) 0xEE, (byte) 0x19, (byte) 0x26,
			(byte) 0xDB, (byte) 0x84, (byte) 0x6F, (byte) 0xA8, (byte) 0xFE,
			(byte) 0xB7, (byte) 0x99, (byte) 0x37, (byte) 0x1F, (byte) 0x93,
			(byte) 0xB2, (byte) 0x45, (byte) 0xF7, (byte) 0xEF, (byte) 0x95,
			(byte) 0x00, (byte) 0x64, (byte) 0xDE, (byte) 0xD9, (byte) 0x54,
			(byte) 0xE7, (byte) 0x0D, (byte) 0xA1, (byte) 0xA5, (byte) 0x67,
			(byte) 0x6F, (byte) 0x1C, (byte) 0x63, (byte) 0xFB, };

	private static final byte[] DP = { (byte) 0xA9, (byte) 0xEF, (byte) 0xEE,
			(byte) 0x7B, (byte) 0x77, (byte) 0x1C, (byte) 0x38, (byte) 0xAE,
			(byte) 0x48, (byte) 0xA6, (byte) 0xB1, (byte) 0x19, (byte) 0xCD,
			(byte) 0x5F, (byte) 0x08, (byte) 0x8F, (byte) 0x71, (byte) 0x52,
			(byte) 0xCF, (byte) 0x4A, (byte) 0x99, (byte) 0x5B, (byte) 0x2F,
			(byte) 0x45, (byte) 0xED, (byte) 0x14, (byte) 0x07, (byte) 0x88,
			(byte) 0xE1, (byte) 0xCE, (byte) 0xDE, (byte) 0xE0, (byte) 0x68,
			(byte) 0xCC, (byte) 0xB1, (byte) 0x35, (byte) 0x3E, (byte) 0x3F,
			(byte) 0xE2, (byte) 0xDC, (byte) 0x3B, (byte) 0xE9, (byte) 0x4A,
			(byte) 0xB3, (byte) 0xF2, (byte) 0x53, (byte) 0x42, (byte) 0xB8,
			(byte) 0xFB, (byte) 0x66, (byte) 0xAD, (byte) 0x94, (byte) 0xC2,
			(byte) 0x86, (byte) 0xDA, (byte) 0x04, (byte) 0x46, (byte) 0x37,
			(byte) 0x8D, (byte) 0x27, (byte) 0x5B, (byte) 0xC0, (byte) 0xB2,
			(byte) 0x6F, (byte) 0x38, (byte) 0x0E, (byte) 0x4E, (byte) 0x76,
			(byte) 0x4D, (byte) 0x87, (byte) 0x57, (byte) 0x37, };

	private static final byte[] Q = { (byte) 0xF9, (byte) 0x1D, (byte) 0x89,
			(byte) 0x0A, (byte) 0x12, (byte) 0x37, (byte) 0x41, (byte) 0x14,
			(byte) 0xD9, (byte) 0x31, (byte) 0xF2, (byte) 0x5A, (byte) 0x63,
			(byte) 0x21, (byte) 0xEC, (byte) 0x34, (byte) 0x38, (byte) 0x6C,
			(byte) 0xE7, (byte) 0x53, (byte) 0x9C, (byte) 0xF8, (byte) 0xB9,
			(byte) 0xB8, (byte) 0x96, (byte) 0x5C, (byte) 0xF7, (byte) 0x8D,
			(byte) 0xAF, (byte) 0xEE, (byte) 0xC5, (byte) 0x68, (byte) 0x0C,
			(byte) 0x4F, (byte) 0x73, (byte) 0x1E, (byte) 0x86, (byte) 0xB4,
			(byte) 0x32, (byte) 0x60, (byte) 0xE5, (byte) 0x25, (byte) 0xBA,
			(byte) 0x49, (byte) 0x46, (byte) 0xA7, (byte) 0x7D, (byte) 0x7E,
			(byte) 0x13, (byte) 0x65, (byte) 0xD2, (byte) 0xAF, (byte) 0x5D,
			(byte) 0x8B, (byte) 0x68, (byte) 0xF3, (byte) 0xE7, (byte) 0x5F,
			(byte) 0x80, (byte) 0x97, (byte) 0x4E, (byte) 0x45, (byte) 0xFF,
			(byte) 0x5A, (byte) 0x94, (byte) 0x72, (byte) 0x78, (byte) 0x1B,
			(byte) 0x26, (byte) 0xAA, (byte) 0x95, (byte) 0xF9, };

	private static final byte[] P = { (byte) 0xFE, (byte) 0xE7, (byte) 0xE5,
			(byte) 0xB9, (byte) 0x32, (byte) 0xAA, (byte) 0x55, (byte) 0x05,
			(byte) 0x6C, (byte) 0xFA, (byte) 0x09, (byte) 0xA6, (byte) 0xB4,
			(byte) 0x0E, (byte) 0x8C, (byte) 0xD7, (byte) 0x29, (byte) 0xFC,
			(byte) 0x36, (byte) 0xEF, (byte) 0xE6, (byte) 0x08, (byte) 0xC6,
			(byte) 0xE8, (byte) 0xE3, (byte) 0x9E, (byte) 0x0B, (byte) 0x4D,
			(byte) 0x52, (byte) 0xB6, (byte) 0x4E, (byte) 0x50, (byte) 0x9D,
			(byte) 0x33, (byte) 0x09, (byte) 0xCF, (byte) 0xDD, (byte) 0x5F,
			(byte) 0xD4, (byte) 0x4A, (byte) 0x59, (byte) 0xDD, (byte) 0xF0,
			(byte) 0x0D, (byte) 0xEB, (byte) 0x7C, (byte) 0xE4, (byte) 0x15,
			(byte) 0x79, (byte) 0x1A, (byte) 0x04, (byte) 0x5F, (byte) 0x23,
			(byte) 0xCA, (byte) 0x47, (byte) 0x06, (byte) 0x69, (byte) 0x53,
			(byte) 0x53, (byte) 0xBB, (byte) 0x09, (byte) 0xA1, (byte) 0x0B,
			(byte) 0xA6, (byte) 0xD4, (byte) 0x15, (byte) 0x75, (byte) 0xB1,
			(byte) 0x74, (byte) 0x4B, (byte) 0x02, (byte) 0xD3, };

	private static final byte ZERO = 0;

	private RSAPrivateCrtKey privCrtKey;
	private KeyPair rsaKeyPair;

	private Signature sig;

	private Cipher cipher_RSA;

	public RSA() {
		short keyLen = (short) (PQ.length * 8 * 2); 
		privCrtKey = (RSAPrivateCrtKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_CRT_PRIVATE, keyLen, false);

		try {
			privCrtKey.setPQ(PQ, ZERO, (short) PQ.length);
			privCrtKey.setDQ1(DQ, ZERO, (short) DQ.length);
			privCrtKey.setDP1(DP, ZERO, (short) DP.length);
			privCrtKey.setQ(Q, ZERO, (short) Q.length);
			privCrtKey.setP(P, ZERO, (short) P.length);
			privCrtKey.isInitialized();
	
			rsaKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
			rsaKeyPair.genKeyPair();
		} catch (CryptoException e) {
			short re = e.getReason();
			ISOException.throwIt(re);
		}
		
		sig = Signature.getInstance(Signature.ALG_RSA_SHA_ISO9796, false);

		cipher_RSA = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
	}
	
	public PrivateKey getPriKey() {
		return rsaKeyPair.getPrivate();
	}
	
	public PublicKey getPubKey() {
		return rsaKeyPair.getPublic();
	}

	public void initCrypt(boolean isEncrypt) {
		if (isEncrypt)
			cipher_RSA.init(rsaKeyPair.getPrivate(), Cipher.MODE_ENCRYPT);
		else
			cipher_RSA.init(rsaKeyPair.getPublic(), Cipher.MODE_DECRYPT);
	}
	
	public short getCipher(byte[] inBuff, short inOff, short inLen, 
			byte[] outBuff, short outOff) {
		return cipher_RSA.doFinal(inBuff, inOff, inLen, outBuff, outOff);
	}
	
	public void initSign() {
		sig.init(privCrtKey, Signature.MODE_SIGN);
	}
	
	public short getSign(byte[] inBuff, short inOff, short inLen, byte[] outBuff, short outOff) {
		return sig.sign(inBuff, inOff, inLen, outBuff, outOff);
	}
}
