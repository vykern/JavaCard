package testApi;

import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class DES {

	private static final short IV_LEN_8 = 8;
	private static final short ZERO = 0;
	private static byte[] tmpKey = new byte[] { 
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
			0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, };

	private Signature desSig;
	private Cipher cipher_ECB_M2;
	private DESKey desKey;
	private byte[] ivData;

	public DES() {
		desSig = Signature.getInstance(
				Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
		
		cipher_ECB_M2 = Cipher.getInstance(
				Cipher.ALG_DES_ECB_ISO9797_M2, false);
		
		desKey = (DESKey)KeyBuilder.buildKey(
				KeyBuilder.TYPE_DES, 
				KeyBuilder.LENGTH_DES, false);
		
		desKey.setKey(tmpKey, ZERO);
		
		ivData = new byte[IV_LEN_8];
	}
	
	void initCrypt(boolean isEncrypt) {
		if (isEncrypt) {
			cipher_ECB_M2.init(desKey, Cipher.MODE_ENCRYPT);
		}
		else {
			cipher_ECB_M2.init(desKey, Cipher.MODE_DECRYPT);
		}
	}

	public short getCipher(byte[] inBuff, short inOff, short inLen, 
			byte[] outBuff, short outOff) {
		return cipher_ECB_M2.doFinal(inBuff, inOff, inLen, outBuff, outOff);
	}
	
	public void initSign() {
		desSig.init(desKey, Signature.MODE_SIGN, ivData, ZERO, IV_LEN_8);
	}
	
	public short getSign(byte[] inBuff, short inOff, short inLen,
			byte[] outBuff, short outOff) {
		short outLen;
		outLen = desSig.sign(inBuff, inOff, inLen, outBuff, outOff);
		return outLen;
	}
}
