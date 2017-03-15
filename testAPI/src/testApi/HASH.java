package testApi;

import javacard.security.MessageDigest;

public class HASH {

	private MessageDigest md;

	public HASH() {
		md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
	}
	
	public short getMsgDigest(byte[] inBuff, short inOff, short inLen,
			byte[] outBuff, short outOff) {
		return md.doFinal(inBuff, inOff, inLen, outBuff, outOff);
	}

}
