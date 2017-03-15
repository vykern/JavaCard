/**
 * 
 */
package testApi;

import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;

/**
 * @author LiuWeiwei
 *
 */
public class TestApi extends Applet {
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new TestApi(bArray, bOffset, bLength);
	}

	private DES des;
	private RSA rsa;
	private AES aes;
	private HASH hash;
	private ECA eca;

	public TestApi(byte[] bArray, short bOffset, byte bLength) {
		byte aidLen = bArray[bOffset++];
		short aidOff = bOffset;
//		des = new DES();
//		rsa = new RSA();
		aes = new AES();
//		hash = new HASH();
//		eca = new ECA();
		register(bArray, aidOff, aidLen);
	}
	
 	public void process(APDU apdu) {
		if (selectingApplet()) {
			AID aid = JCSystem.getAID();
			byte[] apduBuff = apdu.getBuffer();
			apdu.setOutgoing();
			short aidLen = aid.getBytes(apduBuff, (short) 0);
			apdu.setOutgoingLength(aidLen);
			apdu.sendBytes((short) 0, aidLen);
			return;
		}

		byte[] buf = apdu.getBuffer();
		try {
			switch (buf[ISO7816.OFFSET_INS]) {
			case (byte) 0x00:
				if (des != null)
					handleDES(apdu);
				break;
			case (byte) 0x01:
				if (rsa != null)
					handleRSA(apdu);
				break;
			case (byte) 0x02:
				if (aes != null)
					handleAES(apdu);
				break;
			case (byte) 0x03:
				if (hash != null)
					handleHASH(apdu);
				break;
			case (byte) 0x04:
				if (eca != null) 
					handleECA(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}
		catch (CryptoException e) {
			short err = e.getReason();
			ISOException.throwIt((short) (0x6f00 + err));
		}
	}

	private void handleECA(APDU apdu) {
		byte[] buff = apdu.getBuffer();
		short lc = apdu.setIncomingAndReceive();
		short off = ISO7816.OFFSET_CDATA;
		short outOff = (short) (lc + off);
		short outLen = 0;
		switch(buff[ISO7816.OFFSET_P1]) {
		case 1:
			short inLen = lc; 
			short inOff = ISO7816.OFFSET_CDATA;
			eca.initSign(true);
			outLen = eca.getSign(buff, inOff, inLen, buff, outOff);
			break;
		case 2:
			short msgOff = off;
			short msgLen = (short) (buff[ISO7816.OFFSET_P2]);
			short signOff = (short) (off + msgLen);
			short signLen = (short) (lc - msgLen);
			eca.initSign(false);
			if (!eca.verifySig(buff, msgOff, msgLen, buff, signOff, signLen))
				ISOException.throwIt((short) 0x6a80);
			else 
				return;
			break;
			default:
				break;
		}
		apdu.setOutgoingAndSend(outOff, outLen);
	}

	private void handleAES(APDU apdu) {
		byte[] buff = apdu.getBuffer();
		short inLen = apdu.setIncomingAndReceive();
		short inOff = ISO7816.OFFSET_CDATA;
		short outOff = (short) (inOff + inLen);
		short outLen = 0;
		switch(buff[ISO7816.OFFSET_P1]) {
		case 1:
			aes.initCrypt(true);
			outLen = aes.getCipher(buff, inOff, inLen, buff, outOff);
			break;
		case 2:
			aes.initCrypt(false);
			outLen = aes.getCipher(buff, inOff, inLen, buff, outOff);
			break;
		case 3:
			aes.initSign();
			outLen = des.getSign(buff, inOff, inLen, buff, outOff);
			break;
			default:
				break;
		}
		apdu.setOutgoingAndSend(outOff, outLen);
	}

	private void handleRSA(APDU apdu) {
		byte[] buff = apdu.getBuffer();
		short inLen = apdu.setIncomingAndReceive();
		short inOff = ISO7816.OFFSET_CDATA;
		short outOff = (short) (inOff + inLen);
		short outLen = 0;
		switch(buff[ISO7816.OFFSET_P1]) {
		case 1:
			rsa.initCrypt(true);
			outLen = rsa.getCipher(buff, inOff, inLen, buff, outOff);
			break;
		case 2:
			rsa.initCrypt(false);
			outLen = rsa.getCipher(buff, inOff, inLen, buff, outOff);
			break;
		case 3:
			rsa.initSign();
			outLen = des.getSign(buff, inOff, inLen, buff, outOff);
			break;
			default:
				break;
		}
		apdu.setOutgoingAndSend(outOff, outLen);
	}

	private void handleDES(APDU apdu) {
		byte[] buff = apdu.getBuffer();
		short inLen = apdu.setIncomingAndReceive();
		short inOff = ISO7816.OFFSET_CDATA;
		short outOff = (short) (inOff + inLen);
		short outLen = 0;
		switch(buff[ISO7816.OFFSET_P1]) {
		case 1:
			des.initCrypt(true);
			outLen = des.getCipher(buff, inOff, inLen, buff, outOff);
			break;
		case 2:
			des.initCrypt(false);
			outLen = des.getCipher(buff, inOff, inLen, buff, outOff);
			break;
		case 3:
			des.initSign();
			outLen = des.getSign(buff, inOff, inLen, buff, outOff);
			break;
			default:
				break;
		}
		apdu.setOutgoingAndSend(outOff, outLen);
	}

	private void handleHASH(APDU apdu) {
		byte[] buff = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short inOff = ISO7816.OFFSET_CDATA;
		short inLen = buff[ISO7816.OFFSET_LC];
		short outOff = (short) (inOff + inLen);
		short outLen = 0;
		outLen = hash.getMsgDigest(buff, inOff, inLen, buff, outOff);
		apdu.setOutgoingAndSend(outOff, outLen);
	}
}