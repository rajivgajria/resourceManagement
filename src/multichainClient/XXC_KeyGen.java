package multichainClient;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

/**
 * This is the Class which generates the Public and private keys of the entities and helps 
 * in encryption and decryption
 * @author 
 *
 */
public class XXC_KeyGen{
    public static final String RSAALGORITHM = "RSA";
    public static final String SHA256 = "SHA-256";
    public static final String AES = "AES";
    public static final int AES_KEYLENGTH = 128;
    public static final String AES_ALGO = "AES/CBC/PKCS5PADDING";
    public static final String NEWTASK = "new";
    public static final String EncryptTask = "encrypt";

    private KeyPair generatedKeyPair;
    private String SHAString = null;

    public KeyPair getGeneratedKeyPair(){
	return generatedKeyPair;
    }

    public void setGeneratedKeyPair(KeyPair generatedKeyPair){
	this.generatedKeyPair = generatedKeyPair;
    }

    public void setSHAString(String sHAString){
	this.SHAString = sHAString;
    }

    /**
     * This method Generates the Hash of the id, creates a key pair and stores the pair in the 
     * path which prefix as usertype-hash-public / private.key
     * @param path
     * @param userType
     * @param id
     * @param task
     */
    public XXC_KeyGen(String path, char userType, String id, String task){

	if (NEWTASK.equalsIgnoreCase(task)){
	    try{

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSAALGORITHM);

		keyGen.initialize(2048);
		generatedKeyPair = keyGen.genKeyPair();
		SHAString = getSHA256HexString(id);
		String filenamePrefix = generateFilenamePrefix(userType);
		SaveKeyPair(path, filenamePrefix, generatedKeyPair);

	    } catch (Exception e){
		e.printStackTrace();
		return;
	    }
	} else if (task == "encrypt"){
	    try{

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSAALGORITHM);

		keyGen.initialize(1024);
		KeyPair loadedKeyPair = LoadKeyPair(path, RSAALGORITHM);

		byte[] publicKey = loadedKeyPair.getPublic().getEncoded();
		byte[] privateKey = loadedKeyPair.getPrivate().getEncoded();

		byte[] encryptedData = encrypt(publicKey, "hi this is Visruth here".getBytes());

		System.out.println(new String(encryptedData));

		byte[] decryptedData = decrypt(privateKey, encryptedData);

		System.out.println(new String(decryptedData));

	    } catch (Exception e){
		e.printStackTrace();
		return;
	    }
	}

    }

    public XXC_KeyGen(String path, char documentType, byte[] documentBytes, String task){
	if (task == "new"){
	    try{

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSAALGORITHM);

		keyGen.initialize(2048);
		generatedKeyPair = keyGen.genKeyPair();

		SHAString = getSHA256HexString(documentBytes);
		String filenamePrefix = generateFilenamePrefix(documentType);
		SaveKeyPair(path, filenamePrefix, generatedKeyPair);

	    } catch (Exception e){
		e.printStackTrace();
		return;
	    }
	}
    }

    /**
     * This method generates the prefix for the files to be saved. 
     * @param userType
     * @return
     */
    private String generateFilenamePrefix(char userType){
	return (Character.toString(userType) + "-");
    }

    public byte[] getPublicKeyBytes(){
	return generatedKeyPair.getPublic().getEncoded();
    }

    public byte[] getPrivateKeyBytes(){
	return generatedKeyPair.getPrivate().getEncoded();
    }

    public String getSHAString(){
	return (new String((SHAString)));

    }

    /**
     * This method Method encrypts the input data using the public key and RSA Algorithm. 
     * @param publicKey
     * @param inputData
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] publicKey, byte[] inputData) throws Exception{

	PublicKey key = KeyFactory.getInstance(RSAALGORITHM).generatePublic(new X509EncodedKeySpec(publicKey));

	Cipher cipher = Cipher.getInstance(RSAALGORITHM);
	cipher.init(Cipher.PUBLIC_KEY, key);

	byte[] encryptedBytes = cipher.doFinal(inputData);

	return encryptedBytes;
    }

    public static byte[] decrypt(byte[] privateKey, byte[] inputData) throws Exception{

	PrivateKey key = KeyFactory.getInstance(RSAALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(privateKey));

	Cipher cipher = Cipher.getInstance(RSAALGORITHM);
	cipher.init(Cipher.PRIVATE_KEY, key);

	byte[] decryptedBytes = cipher.doFinal(inputData);

	return decryptedBytes;
    }

    @SuppressWarnings("unused")
    private void dumpKeyPair(KeyPair keyPair){
	PublicKey pub = keyPair.getPublic();
	System.out.println("Public Key: " + getHexString(pub.getEncoded()));

	PrivateKey priv = keyPair.getPrivate();
	System.out.println("Private Key: " + getHexString(priv.getEncoded()));

	Base64.Encoder encoder = Base64.getEncoder();
	System.out.println("privateKey: " + encoder.encodeToString(priv.getEncoded()));
	System.out.println("publicKey: " + encoder.encodeToString(pub.getEncoded()));
    }

    private String getHexString(byte[] b){
	String result = "";
	for (int i = 0; i < b.length; i++){
	    result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
	}
	return result;
    }

    /**
     * This method encodes the keypair and stores in the path directory. 
     * @param path
     * @param filenamePrefix
     * @param keyPair
     * @throws IOException
     */
    private void SaveKeyPair(String path, String filenamePrefix, KeyPair keyPair) throws IOException{
	PrivateKey privateKey = keyPair.getPrivate();
	PublicKey publicKey = keyPair.getPublic();

	// Store Public Key.
	X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
	FileOutputStream fos = new FileOutputStream(path + "/" + filenamePrefix + SHAString + "_public.key");
	fos.write(x509EncodedKeySpec.getEncoded());
	fos.close();

	// Store Private Key.
	PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
	fos = new FileOutputStream(path + "/" + filenamePrefix + SHAString + "_private.key");
	fos.write(pkcs8EncodedKeySpec.getEncoded());
	fos.close();
    }

    private KeyPair LoadKeyPair(String path, String algorithm)
	    throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
	// Read Public Key.
	File filePublicKey = new File(path + "_public.key");
	FileInputStream fis = new FileInputStream(path + "_public.key");
	byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
	fis.read(encodedPublicKey);
	fis.close();

	// Read Private Key.
	File filePrivateKey = new File(path + "_private.key");
	fis = new FileInputStream(path + "_private.key");
	byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
	fis.read(encodedPrivateKey);
	fis.close();
	// Generate KeyPair.
	KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
	X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
	PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
	PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
	return new KeyPair(publicKey, privateKey);
    }

    private static final char[] hex = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
	    'f' };

    public static String byteArray2Hex(byte[] bytes){
	StringBuffer sb = new StringBuffer(bytes.length * 2);
	for (final byte b : bytes){
	    sb.append(hex[(b & 0xF0) >> 4]);
	    sb.append(hex[b & 0x0F]);
	}
	return sb.toString();
    }
    
    /**
     * This method generates the hash of the string and returns the hexadecimal equivalent. 
     * @param stringToEncrypt
     * @return
     * @throws NoSuchAlgorithmException
     */
    public String getSHA256HexString(String stringToEncrypt) throws NoSuchAlgorithmException{
	MessageDigest messageDigest = MessageDigest.getInstance(SHA256);
	messageDigest.update(stringToEncrypt.getBytes());
	return byteArray2Hex(messageDigest.digest());
    }

    public String getSHA256HexString(byte[] documentBytes) throws NoSuchAlgorithmException{
	MessageDigest messageDigest = MessageDigest.getInstance(SHA256);
	messageDigest.update(documentBytes);
	return byteArray2Hex(messageDigest.digest());

    }

    public static PrivateKey getPrivateKeyFromEncodedSpec(String filename) throws Exception{
	byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	KeyFactory kf = KeyFactory.getInstance(RSAALGORITHM);
	return kf.generatePrivate(spec);
    }

    public static PublicKey getPublicKeyFromEncodedSpec(String filename) throws Exception{
	byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	KeyFactory kf = KeyFactory.getInstance(RSAALGORITHM);
	return kf.generatePublic(spec);
    }
    
    

}