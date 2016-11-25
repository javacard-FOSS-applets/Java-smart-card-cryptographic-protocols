package hmacPackage;

import javacard.framework.*;
import javacard.security.*;

/* 
 * class TestApplet 
 */
public class HMACApplet extends javacard.framework.Applet 
{
	// CLA Byte
	final static byte TEST_CLA = (byte) 0xB0;
	// Verify PIN
	final static byte INS_HELLO = (byte) 0x20;
	final static byte INS_HASH = (byte) 0x30;
	final static byte INS_HMAC = (byte) 0x40;
	final static byte INS_HASHCHAIN = (byte) 0x50;

	public static void install (byte [] barray, short bOffset, byte bLength) 
	{
		(new HMACApplet()).register(barray,(short) (bOffset + 1), barray[bOffset]);
	}

	// Process the command APDU
	public void process(APDU apdu) 
	{
		byte [] buffer = apdu.getBuffer();
		
		if((buffer[ISO7816.OFFSET_CLA] == 0) && (buffer [ISO7816. OFFSET_INS] == (byte) (0xa4)))
		{
			return;
		}
	
		// Validate the CLA byte
		if(buffer[ISO7816.OFFSET_CLA] != TEST_CLA)
		{
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		byte[] helloWorld = {'H','e','l','l','o',' ','W','o','r','l','d',};
		byte[] msg = {'T', 'h', 'e', ' ', 'q', 'u', 'i', 'c', 'k', ' ', 'b', 'r', 'o', 'w', 'n', ' ', 'f', 'o', 'x', ' ', 'j', 'u', 'm', 'p', 's', ' ', 'o', 'v', 'e', 'r', ' ', 't', 'h', 'e', ' ', 'l', 'a', 'z', 'y', ' ', 'd', 'o', 'g',};
		byte[] hChainSeed1 = {'s', 'e', 'e', 'd', ' ', 'o', 'n', 'e', };
		byte[] hChainSeed2 = {'s', 'e', 'e', 'd', ' ', 't', 'w', 'o', };
		// Select the appropriate instruction byte (INS)
		switch(buffer[ISO7816.OFFSET_INS])
		{
			case INS_HELLO: getHelloWorld(apdu, helloWorld); return;
			case INS_HASH:
				if(buffer[ISO7816.OFFSET_P1] <= 6)
				{
					if(buffer[ISO7816.OFFSET_LC] == 0)
						hash(apdu, buffer[ISO7816.OFFSET_P1], helloWorld, true); 
					else
					{
						short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
						if (bytesLeft < (short)1) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );

						short readCount = apdu.setIncomingAndReceive();
						byte[] message = new byte[readCount];
						for (byte i=0; i <  readCount; i++)
						{
							message[i] = buffer[ISO7816.OFFSET_CDATA+i];
						}	
						hash(apdu, buffer[ISO7816.OFFSET_P1], message, true); 
					}
				}
				else ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				return;
		case INS_HMAC:
			if(buffer[ISO7816.OFFSET_P1] <= 6)
			{
				if(buffer[ISO7816.OFFSET_LC] == 0)
					hmac(apdu, buffer[ISO7816.OFFSET_P1], msg); 
				else
				{
					short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
					if (bytesLeft < (short)1) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );

					short readCount = apdu.setIncomingAndReceive();
					byte[] message = new byte[readCount];
					for (byte i=0; i <  readCount; i++)
					{
						message[i] = buffer[ISO7816.OFFSET_CDATA+i];
					}	
					hmac(apdu, buffer[ISO7816.OFFSET_P1], message); 
				}
			}
			else ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
		case INS_HASHCHAIN:
			if(buffer[ISO7816.OFFSET_P1] <= 6)
			{
				if(buffer[ISO7816.OFFSET_P2] == 0)
				{
					GetHashChain(apdu, buffer[ISO7816.OFFSET_P1], hChainSeed1, hChainSeed2, (short)10, (short)3); 
				}
				else
				{
					GetHashChain(apdu, buffer[ISO7816.OFFSET_P1], hChainSeed1, hChainSeed2, (short)10, (short)buffer[ISO7816.OFFSET_P2]); 					
				}
			}
			else ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			return;
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);			
		}
	}

	private void getHelloWorld( APDU apdu, byte[] message)
    {
		byte[] buffer = apdu.getBuffer();
		short length = (short) message.length;
		Util.arrayCopyNonAtomic(message, (short)0, buffer, (short)0, (short) length);
		apdu.setOutgoingAndSend((short)0, length);
    }
	
	private byte[] hash(APDU apdu,byte ALG_NO, byte[] message, boolean showResult) 
	{
		MessageDigest md = MessageDigest.getInstance(ALG_NO, false);
		byte length = (byte) message.length;
	        
		//while (nread != -1) {
		//	md.update(dataBytes, (short)0, length);
	    //};
		// FINALIZE HASH VALUE (WHEN LAST PART OF DATA IS AVAILABLE) 
		// AND OBTAIN RESULTING HASH VALUE 
		byte[] out_hash_array = apdu.getBuffer();
		md.doFinal(message, (short)0, (short)length, out_hash_array, (short)0);
		
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopyNonAtomic(out_hash_array, (short)0, buffer, (short)0, (short) out_hash_array.length);
		
		byte Alg_Len = 0;
		switch(ALG_NO)
		{
			//case 1:Alg_Len = 20; break;
			//case 2:Alg_Len = 16; break;
			case 1:Alg_Len = MessageDigest.LENGTH_SHA; break;
			case 2:Alg_Len = MessageDigest.LENGTH_MD5; break;
			case 3:Alg_Len = MessageDigest.LENGTH_RIPEMD160; break;
			case 4:Alg_Len = MessageDigest.LENGTH_SHA_256; break;
			case 5:Alg_Len = MessageDigest.LENGTH_SHA_384; break;
			case 6:Alg_Len = MessageDigest.LENGTH_SHA_512; break;
			default:ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		
		if(showResult) apdu.setOutgoingAndSend((short)0, (short) Alg_Len);
		byte[] retBuf = new byte[Alg_Len];
		Util.arrayCopyNonAtomic(out_hash_array, (short)0, retBuf, (short)0, (short) Alg_Len);
		return retBuf;
	}
	
	private void hmac(APDU apdu,byte ALG_NO, byte[] message) 
	{
		byte Alg_Len = 0;
		short BlockSize = 0;
		switch(ALG_NO)
		{
			//case 1:Alg_Len = 20;BlockSize = 64; break;
			//case 2:Alg_Len = 16;BlockSize = 64; break;
			case 1:Alg_Len = MessageDigest.LENGTH_SHA; break;
			case 2:Alg_Len = MessageDigest.LENGTH_MD5; break;
			case 3:Alg_Len = MessageDigest.LENGTH_RIPEMD160; break;
			case 4:Alg_Len = MessageDigest.LENGTH_SHA_256; break;
			case 5:Alg_Len = MessageDigest.LENGTH_SHA_384; break;
			case 6:Alg_Len = MessageDigest.LENGTH_SHA_512; break;
			default:ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
	    
	    byte[] key = new byte[BlockSize]; 
	    byte[] kVal = {'k','e','y',};
	    Util.arrayFillNonAtomic(key,(short)0,(byte)0, (byte)0);
	    Util.arrayCopyNonAtomic(kVal, (short)0, key, (short)0, (short)kVal.length);
	    byte IPAD = (byte)0x36;
		byte OPAD = (byte)0x5c;
				
		byte[] part1 = DoXOR(key, OPAD);
		byte[] part2 = DoXOR(key, IPAD);
		byte[] h1 = new byte[(byte)part2.length + (byte)message.length];
		h1 = Concatenation(part2, message);
		
		MessageDigest md = MessageDigest.getInstance(ALG_NO, false);
		byte length = (byte) message.length;

		byte[] h1Hash = apdu.getBuffer();
		md.doFinal(h1, (short)0, (short)h1.length, h1Hash, (short)0);
		
		byte[] h1Hash2 = new byte[Alg_Len];
		Util.arrayCopyNonAtomic(h1Hash, (short)0, h1Hash2, (short)0, (short) Alg_Len);
		byte[] h2 = new byte[(byte)part1.length + (byte)h1Hash2.length];
		
		h2 = Concatenation(part1, h1Hash2);
		
		//md.reset();
		byte[] h2Hash = apdu.getBuffer();
		md.doFinal(h2, (short)0, (short)h2.length, h2Hash, (short)0);
		
		apdu.setOutgoingAndSend((short)0, (short) Alg_Len);
	}
		
	private byte[] Concatenation(byte[] arr1, byte[] arr2)
	{
		byte[] res = new byte[(byte)arr1.length + (byte)arr2.length];
		Util.arrayCopyNonAtomic(arr1, (short)0, res, (short)0, (short) arr1.length);
		Util.arrayCopyNonAtomic(arr2, (short)0, res, (short)arr1.length, (short) arr2.length);
		return res;
	}
	
	private byte[] DoXOR(byte[] Key, byte value)
	{
		short Len = (short)Key.length;
		byte[] res = new byte[Len];
		// (Key XOR value )
		for(short i = 0; i < Len; i++)
		{
			res[i] = (byte) (Key[i] ^ value);
		}	
		return res;
	}
	//--- hash chain function ---
	private void GetHashChain(APDU apdu,byte ALG_NO, byte[] seed1, byte[] seed2, short chainLen, short hashOrder)
	{
		byte Alg_Len = 0;
		switch(ALG_NO)
		{
			//case 1:Alg_Len = 20; break;
			//case 2:Alg_Len = 16; break;
			case 1:Alg_Len = MessageDigest.LENGTH_SHA; break;
			case 2:Alg_Len = MessageDigest.LENGTH_MD5; break;
			case 3:Alg_Len = MessageDigest.LENGTH_RIPEMD160; break;
			case 4:Alg_Len = MessageDigest.LENGTH_SHA_256; break;
			case 5:Alg_Len = MessageDigest.LENGTH_SHA_384; break;
			case 6:Alg_Len = MessageDigest.LENGTH_SHA_512; break;
			default:ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}

		byte[] s1 = getHash(apdu, Alg_Len, ALG_NO, seed1, hashOrder);
		byte[] s2 = getHash(apdu, Alg_Len, ALG_NO, seed2, (short)(chainLen - hashOrder + 1));

				
		byte[] s3 = apdu.getBuffer();//new byte[Alg_Len];
		for(short i = 0; i < Alg_Len; i++)
		{
			s3[i] = (byte)(s1[i] ^ s2[i]);
		}
		
		apdu.setOutgoingAndSend((short)0, (short) Alg_Len);
	}
	
	private byte[] getHash(APDU apdu,short Alg_Len, byte ALG_NO, byte[] seed, short HashCount)
	{
		MessageDigest md = MessageDigest.getInstance(ALG_NO, false);
	        
		byte[] out_hash_array = apdu.getBuffer();
		md.doFinal(seed, (short)0, (short)seed.length, out_hash_array, (short)0);
		
		byte[] s = new byte[Alg_Len];
		for(short i = 0; i < HashCount; i++)
		{
			s = new byte[Alg_Len];
			Util.arrayCopyNonAtomic(out_hash_array, (short)0, s, (short)0, Alg_Len);
			md.doFinal(s, (short)0, (short)s.length, out_hash_array, (short)0);
			
			//s = out_hash_array;
		}
		return s;
	}
}