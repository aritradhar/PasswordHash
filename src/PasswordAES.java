//*************************************************************************************
//*********************************************************************************** *
//author Aritra Dhar 																* *
//Research Engineer																  	* *
//Xerox Research Center India													    * *
//Bangalore, India																    * *
//--------------------------------------------------------------------------------- * * 
///////////////////////////////////////////////// 									* *
//The program will do the following:::: // 											* *
///////////////////////////////////////////////// 									* *
//version 1.0 																		* *
//*********************************************************************************** *
//*************************************************************************************

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;


public class PasswordAES
{
   
    public static int secureCounter = 4096;
    /*
     * get byte[] of the private key by getEncodedMethod(), also supply
     * the password in string object
     * output will be :
     * index 0 : cipher text
     * index 1 : salt
     * index 2 : IV (initialization vector)
     * index 3 : Hash
     * save these 3 in a file
     */
    public static List<byte[]> Encrypt(byte[] privateKey, String passward) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
    {
    	FileWriter fw = new FileWriter("pass.key");
    	
        List<byte[]> outPut = new ArrayList<>();
       
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
       
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
       
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey secretKey = factory.generateSecret(new PBEKeySpec(passward.toCharArray(), salt, secureCounter, 256));
        byte[] secretBytes = secretKey.getEncoded();
       
        byte[] iv = new byte[16];
        sr.nextBytes(iv);
       
       
        SecretKey sec = new SecretKeySpec(secretBytes, 0, 16,  "AES");
        cipher.init(Cipher.ENCRYPT_MODE, sec, new IvParameterSpec(iv));
       
        byte[] ciPherText = cipher.doFinal(privateKey);
       
        
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] passByte = passward.getBytes();
    
        byte[] all = new byte[passByte.length + salt.length + privateKey.length];
        System.arraycopy(passByte, 0, all, 0, passByte.length);
        System.arraycopy(salt, 0, all, passByte.length, salt.length);
        System.arraycopy(privateKey, 0, all, passByte.length + salt.length, privateKey.length);

        //System.out.println(new String(passByte));
        //System.out.println(new String(salt));
        
        
        byte[] hash = digest.digest(all);
       
        outPut.add(ciPherText);
        outPut.add(salt);
        outPut.add(iv);
        outPut.add(hash);
        
        String c = Base64.encodeBase64URLSafeString(ciPherText);
        String s = Base64.encodeBase64URLSafeString(salt);
        String i = Base64.encodeBase64URLSafeString(iv);
        String h = Base64.encodeBase64URLSafeString(hash);
        
        fw.append(c).append("\n").append(s).append("\n").append(i).append("\n").append(h);
        
        fw.close();
        
        return outPut;
    }
   
   
   
    public static byte[] decrypt (List<byte[]> input, String passward) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
    {       
        if(input.size() != 4)
            throw new IllegalArgumentException("Bad arguments");
       
        byte[] cipherText = input.get(0);
        byte[] salt = input.get(1);
        byte[] iv = input.get(2);
        byte[] hash = input.get(3);
       
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey secretKey = factory.generateSecret(new PBEKeySpec(passward.toCharArray(), salt, secureCounter, 256));
        byte[] secretBytes = secretKey.getEncoded();
       
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
       
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretBytes, 0, 16, "AES"), new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(cipherText);
       
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] passByte = passward.getBytes();
        byte[] all = new byte[passByte.length + salt.length + decrypted.length];
        System.arraycopy(passByte, 0, all, 0, passByte.length);
        System.arraycopy(salt, 0, all, passByte.length, salt.length);
        System.arraycopy(decrypted, 0, all, passByte.length + salt.length, decrypted.length);
        
        byte[] hashToCheck = digest.digest(all);
       
        if(!Arrays.equals(hash, hashToCheck))
            throw new RuntimeException("Wrong pssword");
       
        return decrypted;
       
    }
    
    /*
     *this is the new overloaded decrypt method
     *to read from the specified file directly 
     */
    public static byte[] decrypt (String passward) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
    {       

    	BufferedReader br = new BufferedReader(new FileReader("pass.key"));
       
    	String st = "";
    	int counter = 0;
    	byte[] cipherText = null, salt = null, iv = null, hash = null;
    	
    	while((st = br.readLine()) != null)
    	{
    		++counter;
    		
    		switch (counter) 
    		{
			case 1:
				cipherText = Base64.decodeBase64(st);
				break;

			case 2:
				salt = Base64.decodeBase64(st);
				break;

			case 3:
				iv = Base64.decodeBase64(st);
				break;

			case 4:
				hash = Base64.decodeBase64(st);
				break;

			default:
				throw new RuntimeException("Wrong file format");

			}
    	}
       
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey secretKey = factory.generateSecret(new PBEKeySpec(passward.toCharArray(), salt, secureCounter, 256));
        byte[] secretBytes = secretKey.getEncoded();
       
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
       
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretBytes, 0, 16, "AES"), new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(cipherText);
       
       
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] passByte = passward.getBytes();
        byte[] all = new byte[passByte.length + salt.length + decrypted.length];
        System.arraycopy(passByte, 0, all, 0, passByte.length);
        System.arraycopy(salt, 0, all, passByte.length, salt.length);
        System.arraycopy(decrypted, 0, all, passByte.length + salt.length, decrypted.length);
        
        //System.out.println(new String(passByte));
        //System.out.println(new String(salt));
        //System.out.println(new String(decrypted));
        
        byte[] hashToCheck = digest.digest(all);
       
        if(!Arrays.equals(hash, hashToCheck))
            throw new RuntimeException("Wrong pssword");
       
        
        return decrypted;
       
    }
   
    //test
    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
    {
        String text = "Bla Bla";
        Encrypt(text.getBytes("UTF-8"), "abcd");
        System.out.println(new String(decrypt("abcd")));
    }

}