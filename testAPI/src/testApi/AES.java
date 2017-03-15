package testApi;

import javacard.framework.ISOException;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class AES {
	private static byte[] tmpKey = new byte[] { 
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, };

	private Signature sig;
	private Cipher cipher_AES;
	private AESKey aesKey;

	public AES() {
		short err = 0;
		try {
		aesKey = (AESKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_AES, 
				KeyBuilder.LENGTH_AES_128, false);
		}
		catch (CryptoException e){
			err = e.getReason();
			ISOException.throwIt((short) (0x6f00 + err));
		}
		sig = Signature.getInstance(
				Signature.ALG_AES_MAC_128_NOPAD, false);

		cipher_AES = Cipher.getInstance(
				Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

		aesKey.setKey(tmpKey, (short) 0);
	}
	
	public void initCrypt(boolean isEncrypt) {
		if (isEncrypt)
			cipher_AES.init(aesKey, Cipher.MODE_ENCRYPT);
		else
			cipher_AES.init(aesKey, Cipher.MODE_DECRYPT);
	}
	
	public short getCipher(byte[] inBuff, short inOff, short inLen, 
			byte[] outBuff, short outOff) {
		return cipher_AES.doFinal(inBuff, inOff, inLen, outBuff, outOff);
	}
	
	public void initSign() {
		sig.init(aesKey, Signature.MODE_SIGN);
	}
	
	public short getSign(byte[] inBuff, short inOff, short inLen, byte[] outBuff, short outOff) {
		return sig.sign(inBuff, inOff, inLen, outBuff, outOff);
	}

}
