package org.tron.common.crypto.dh25519;

import org.junit.Test;
import org.tron.common.crypto.dh25519.FieldElement;
import org.tron.common.crypto.dh25519.FieldOperations;
import org.tron.common.crypto.dh25519.MontgomeryOperations;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ZksnarkUtils;

public class ScalarMultTests {

	public static byte[] hexToBytes(String s) {
	    return javax.xml.bind.DatatypeConverter.parseHexBinary(s);
	}
	
	byte[] alicePrivateKey=hexToBytes(
			"77076d0a7318a57d"+
			"3c16c17251b26645"+
			"df4c2f87ebc0992a"+
			"b177fba51db92c2a");
	
	byte[] alicePublicKey=hexToBytes(
			"8520f0098930a754"+
			"748b7ddcb43ef75a"+
			"0dbf3a0d26381af4"+
			"eba4a98eaa9b4e6a");
	

	byte[] bobPrivateKey=hexToBytes(
			"5dab087e624a8a4b"+
			"79e17f8b83800ee6"+
			"6f3bb1292618b6fd"+
			"1c2f8b27ff88e0eb");

	byte[] bobPublicKey=hexToBytes(
			"de9edb7d7b7dc1b4"+
			"d35b61c2ece43537"+
			"3f8343c85b78674d"+
			"adfc7e146f882b4f");

	byte[] base=new byte[]{
			9,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0
			};
	
	byte[] aliceBobShared=hexToBytes(
			"4A5D9D5BA4CE2DE1"+
			"728E3BF480350F25"+
			"E07E21C947D19E33"+
			"76F09B3C1E161742");
	
	@Test
	public void scalarMultBaseWithAlicePrivate() {		
		byte[] output=new byte[32];
		MontgomeryOperations.scalarmult(output, 0, alicePrivateKey, 0, base, 0);
		System.out.println(ByteArray.toHexString(output));
	}
	
	@Test
	public void scalarMultBaseWithBobPrivate() {		
		byte[] output=new byte[32];
		MontgomeryOperations.scalarmult(output, 0, bobPrivateKey, 0, base, 0);
		System.out.println(ByteArray.toHexString(output));
	}

	@Test
	public void scalarMultAlicePublicWithBobPrivate() {		
		byte[] output=new byte[32];
		MontgomeryOperations.scalarmult(output, 0, bobPrivateKey, 0, alicePublicKey, 0);
		System.out.println(ByteArray.toHexString(output));
	}
	
	@Test
	public void scalarMultBobPublicWithAlicePrivate() {		
		byte[] output=new byte[32];
		MontgomeryOperations.scalarmult(output, 0, alicePrivateKey, 0, bobPublicKey, 0);
		System.out.println(ByteArray.toHexString(output));
	}

	@Test
	public void scalarMult(){
		byte[] output=new byte[32];
		byte[] esk = ByteArray.fromHexString("90030e70ffb713aee6364a4ba7055efdb88dba0b3f793d1466f55d74375439ff");
		ZksnarkUtils.sort(esk);
		byte[] pkenc = ByteArray.fromHexString("66b42bbaac6949b9687dd562724635d5a5b20dc063ebd346b76050f7877d1501");
		ZksnarkUtils.sort(pkenc);
		MontgomeryOperations.scalarmult(output, 0, esk, 0, base, 0);
		System.out.println(ByteArray.toHexString(output));
	}
}
