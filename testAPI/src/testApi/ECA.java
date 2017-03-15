package testApi;

import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

public class ECA {

	private KeyPair ecKeyPair;
	private Signature ecSign;
	public ECA() {
		ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_128);
		ecKeyPair.genKeyPair();
		ecSign = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
	}

	public short getPriKey(byte[] inBuff, short inOff) {
		ECPrivateKey ecPriKey = (ECPrivateKey) ecKeyPair.getPrivate();
		return ecPriKey.getS(inBuff, inOff); 
	}
	
	void initSign(boolean isSign) {
		if (isSign) 
			ecSign.init(ecKeyPair.getPrivate(), Signature.MODE_SIGN);
		else
			ecSign.init(ecKeyPair.getPublic(), Signature.MODE_VERIFY);
	}
	
	public short getSign(byte[] inBuff, short inOff, short inLen, byte[] outBuff, short outOff) {
		short sigLen = ecSign.sign(inBuff, inOff, inLen, outBuff, outOff);
		ecSign.init(ecKeyPair.getPublic(), Signature.MODE_VERIFY);
		if (!ecSign.verify(inBuff, inOff, inLen, outBuff, outOff, sigLen))
			ISOException.throwIt((short) 0x6a80);
		
		return sigLen;
	}
	
	public boolean verifySig(byte[] inBuff, short inOff, short inLen, 
			byte[] sigBuff, short sigOffset, short sigLength) {
		return ecSign.verify(inBuff, inOff, inLen, sigBuff, sigOffset, sigLength);
	}
}
