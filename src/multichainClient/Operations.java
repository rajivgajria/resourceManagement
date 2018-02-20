package multichainClient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.json.simple.JSONObject;

public class Operations{
    private static final String STREAM1 = "teststream1";
    private static final String STREAM2 = "teststream2";
    private static final String STREAM3 = "teststream3";
    private static final String STREAM4 = "teststream4";
    private static final String STREAM5 = "teststream5";
    private static final String STREAM6 = "teststream6";
    
    public static final String newTask = "new";
    public static final String unsuccessful = "Unsuccessful";
    public static final String ERROR = "error";
    
    @SuppressWarnings("unused")
    private String getHexString(byte[] b){
	String result = "";
	for (int i = 0; i < b.length; i++){
	    result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
	}
	return result;
    }

    /**
     * This method generates the key pair for the user and then publishes the public key of the user against its 
     * hash in Stream 1
     * 
     * @param filePath - it is the path where the public and the private keys of the users are stored. 
     * @param signInAuthType - this is the type of the user Accepted values are C, E, S, I 
     * @throws IOException 
     */
    public void registerUser(String filePath, char signInAuthType) throws IOException{
	RPCClient client = new RPCClient();
	
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	try{
	    System.out.println("Enter your ID: ");
	    String id = br.readLine();
	    XXC_KeyGen keyGen = new XXC_KeyGen(filePath, signInAuthType, id, "new");
	    byte[] pubKey = keyGen.getPublicKeyBytes();
	    String SHAString = keyGen.getSHAString();
	    
	    System.out.println(client.publishToStreamForKey(STREAM1, signInAuthType + "-" + SHAString, pubKey));
	} catch (Exception e){
	    e.printStackTrace();
	}
	
    }

    public boolean checkUser(char signInAuthType, String id) throws Exception{
	RPCClient client = new RPCClient();
	boolean userExists = false;
	try{
	    String SUID = getSHA256String(id);
	    String output = client.getLatestStreamKeyItemsData(STREAM1, multichainApp.Student + multichainApp.Separator + SUID);
	    System.out.println("22 - " + Hex.decodeHex(output.toCharArray()));
	    if (ERROR.equalsIgnoreCase(output))
		return userExists;
	    else{
		userExists = true;
		return userExists;
	    }
		
	} catch (Exception ex){
	    System.out.println("There was some Error in checking the user");
	    ex.printStackTrace();
	    throw ex;
	}
	
    }

    /**
     * This method Stores a Sample PDF as the Certificate offered by the Course Provider to the user
     * @param filePath
     * @param signInAuthType
     * @throws Exception
     */
    public void storeCertificate(String filePath, char signInAuthType)throws Exception{
	RPCClient client = new RPCClient();
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	try{
        	    System.out.println("Enter your CP ID: ");
        	    String cpId = br.readLine();
        	    String cpSHA = getSHA256String(cpId);
        	    //This Line of code checks whether the Course Provider Exists or not
        	    String cpOutput = client.getLatestStreamKeyItemsData(STREAM1,
        		    	      multichainApp.CourseProvider + multichainApp.Separator + cpSHA);
        	    
        	    //This code checks whether the Student exists or not and fetches its public key from the stream
        	    System.out.println("Enter Student's ID: ");
        	    String studentId = br.readLine();
        	    String studentSHA = getSHA256String(studentId);
        	    String pubKeyStudent = client.getLatestStreamKeyItemsData(STREAM1,
        		    		   multichainApp.Student + multichainApp.Separator + studentSHA);
        	    //The data is decoded from the hexadecimal form back to the byte array in order to use the Public key. 
        	    byte[] pubKeyStudentBytes = Hex.decodeHex(pubKeyStudent.toCharArray());

        	    if (ERROR.equalsIgnoreCase(cpOutput) | ERROR.equalsIgnoreCase(pubKeyStudent)){
                		System.out.println("ID not found.");
                		return;
        	    } else{
        			// Storing the Signature of the Certificate in Stream 2 
                		System.out.println("Enter location of certificate:");
                		// TODO This is a Sample certificate that is stored in the Stream. In Future there should be some 
                		//method that will generate individual certificates. 
                		Path certFilePath = Paths.get("/home/rajiv/Downloads/Certificate.pdf");
                		byte[] pdfBytes = Files.readAllBytes(certFilePath);
                		//generate the Hash of the Document
                		String documentSHASignature = getSHA256String(pdfBytes);
                		System.out.println("The initial Document SHA String is as follows");
                		System.out.println(documentSHASignature.substring(0,10));
                		//generate the key pair of the Documents
                		XXC_KeyGen documentKeyGen = new XXC_KeyGen(filePath, multichainApp.Document.charAt(0), 
                								pdfBytes, newTask);
                		byte[] documentPublicKey = documentKeyGen.getPublicKeyBytes();
                		byte[] documentPrivateKey = documentKeyGen.getPrivateKeyBytes();
                		//Encrypt the Document hash using the Public Key of the Document. 
                		byte[] encryptedDocumentSHA = XXC_KeyGen.encrypt(documentPublicKey, 
                									documentSHASignature.getBytes());
                		//Encrypt the Document's Private Key using an AES Algorithm. 
                		HashMap<String, String> aesInfo = encryptDocumentPivateKey(documentPrivateKey);
                		//This Code publishes the Encrypted hash of the Document against the Student ID Hash
                		String statusTxIdItems = client.publishToStreamForKey(STREAM2, studentSHA, encryptedDocumentSHA);
                		if (unsuccessful.equalsIgnoreCase(statusTxIdItems)){
                        		System.out.println("Error storing in stream teststream2");
                        		return;
                		} 
                		else{
                		    	// Storing the private key of the document by encrypting it with AES
                        		System.out.println("The length of the Document private key is "+documentPrivateKey.length);
                        		byte[] encryptedDocPrivKey = Base64.decodeBase64(aesInfo.get(multichainApp.documentPrivateKey));
                        		//This code stores the Encrypted Private Key of the Document against the Hash of the Document
                        		String statusTxIdAccess = client.publishToStreamForKey(STREAM5, documentSHASignature , encryptedDocPrivKey);
                        	
                        	//This code provides the Access of the Document to the Student to which it belongs. 
                        	if (unsuccessful.equalsIgnoreCase(statusTxIdAccess)){
                        		System.out.println("Error storing data in stream Stream 5");
                        		return;
                        	} 
                        	else{
                        		System.out.println(statusTxIdAccess);
                        		byte [] aesKey = Base64.decodeBase64(aesInfo.get(multichainApp.AES_KEY));
                        		//This line Encrypts the AES Secret key of the Private Key of the Document with the Students' Public Key
                        		byte[] encryptedAESKey = XXC_KeyGen.encrypt(pubKeyStudentBytes, aesKey);
                        		String encryptedAESKeyBase64 = Base64.encodeBase64String(encryptedAESKey);
                        		//This object represents the Access Details of the Document in Json Format for the Student
                        		JSONObject docAccessDetails = new JSONObject();
                        		docAccessDetails.put(multichainApp.AES_KEY, encryptedAESKeyBase64);
                        		docAccessDetails.put(multichainApp.documentID, documentSHASignature);
                        		//docAccessDetails.put(multichainApp.AES_IV, aesInfo.get(multichainApp.AES_IV));
                        		byte[] docAccessDetailsBytes = docAccessDetails.toJSONString().getBytes();
                        		String statusTxID = client.publishToStreamForKey(STREAM3, studentSHA, docAccessDetailsBytes);
                        		if (unsuccessful.equalsIgnoreCase(statusTxIdAccess)){
                                		System.out.println("Error Storing data in stream Stream 3");
                                		return;
                        		} 
                        		else{
                        		    System.out.println("Data Stored in Stream 3 with ID:"+statusTxID);
                        		}
                        	}
        
        		}
        	    }
	} catch (Exception e){
	    e.printStackTrace();

	}
    }

    /**
     * This method helps the user of the system to Check the access the certificate from Blockchain
     * Assumption is that the 
     * @param signInAuthType
     */
    public void checkAccessCertificate(){
	RPCClient client = new RPCClient();
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	try{
    	    	System.out.println("Enter the Student's ID: ");
    	    	String studentId = br.readLine();
    	    	String studentSHA = getSHA256String(studentId);
    	    	String studentPublicKey = client.getLatestStreamKeyItemsData(STREAM1,
    		    		   multichainApp.Student + multichainApp.Separator + studentSHA);
    	    	byte[] studentPublicKeyBytes = Hex.decodeHex(studentPublicKey.toCharArray());
    	    	
    	    	
    	    	}catch (Exception e){
	    e.printStackTrace();
	}
    }

    public void provideAccessCertificate(){
	RPCClient client = new RPCClient();
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	try{
	    System.out.println("Enter Student's ID: ");
	    String sId = br.readLine();
	    String sSHA = getSHA256String(sId);
	    String sOutput = client.getLatestStreamKeyItemsData("test_pubkeys", "S-" + sSHA);

	    System.out.println("Enter your CP's ID: ");
	    String cpId = br.readLine();
	    String cpSHA = getSHA256String(cpId);
	    String cpOutput = client.getLatestStreamKeyItemsData("test_pubkeys", "C-" + cpSHA);

	    if (cpOutput == "error" | sOutput == "error"){
		System.out.println("ID not found.");
		return;
	    }
	} catch (Exception e){
	    e.printStackTrace();
	}
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

    public String getSHA256String(String stringToEncrypt) throws NoSuchAlgorithmException{
	MessageDigest messageDigest = MessageDigest.getInstance(XXC_KeyGen.SHA256);
	messageDigest.update(stringToEncrypt.getBytes());
	return byteArray2Hex(messageDigest.digest());
    }

    public String getSHA256String(byte[] dataBytes)throws NoSuchAlgorithmException{
	MessageDigest messageDigest = MessageDigest.getInstance(XXC_KeyGen.SHA256);
	messageDigest.update(dataBytes);
	return byteArray2Hex(messageDigest.digest());
    }
    
    /**
     * This method uses AES Algorithm to encrypt the Private key of the Document
     * and returns a map which contains the AES Secret key and the Document Private Key  
     * @param documentPrivateKey
     * @return
     * @throws Exception
     */
    public HashMap<String,String> encryptDocumentPivateKey(byte[] documentPrivateKey)throws Exception{
	HashMap<String, String> aesInfo = new HashMap<String,String>();
	try{
	    /**
		 * Step 1. Generate an AES key using KeyGenerator Initialize the
		 * keysize to 128 bits (16 bytes)
		 * 
		 */
		KeyGenerator keyGen = KeyGenerator.getInstance(XXC_KeyGen.AES);
		keyGen.init(XXC_KeyGen.AES_KEYLENGTH);
		SecretKey secretKey = keyGen.generateKey();
		String secretKeyBase64 =  Base64.encodeBase64String(secretKey.getEncoded());

		/**
		 * Step 2. Generate an Initialization Vector (IV) 
		 * 		a. Use SecureRandom to generate random bits
		 * 		   The size of the IV matches the blocksize of the cipher (128 bits for AES)
		 * 		b. Construct the appropriate IvParameterSpec object for the data to pass to Cipher's init() method
		 */

		
		// Save the IV bytes or send it in plaintext with the encrypted data so you can decrypt the data later
		byte[] iv = new byte[XXC_KeyGen.AES_KEYLENGTH / 8];
		SecureRandom prng = new SecureRandom();
		prng.nextBytes(iv);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		String ivBaseEncodedString = Base64.encodeBase64String(iv);
		/**
		 * Step 3. Create a Cipher by specifying the following parameters
		 * 		a. Algorithm name - here it is AES 
		 * 		b. Mode - here it is CBC mode 
		 * 		c. Padding - e.g. PKCS7 or PKCS5
		 */

		// Must specify the mode explicitly as most JCE providers default to ECB mode!!
		Cipher aesCipherForEncryption = Cipher.getInstance(XXC_KeyGen.AES_ALGO); 

		/**
		 * Step 4. Initialize the Cipher for Encryption
		 */

		//aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
		aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey);

		/**
		 * Step 5. Encrypt the Data 
		 * 		a. Declare / Initialize the Data. Here the data is of type String 
		 * 		b. Convert the Input Text to Bytes 
		 * 		c. Encrypt the bytes using doFinal method
		 */
		
		
		byte[] encryptedPrivateKey = aesCipherForEncryption.doFinal(documentPrivateKey);
		// b64 is done differently on Android
		String encodedPrivKey = org.apache.commons.codec.binary.Base64.encodeBase64String(encryptedPrivateKey);
		System.out.println("Cipher Text generated using AES is "+ encodedPrivKey);
		
		aesInfo.put(multichainApp.AES_KEY, secretKeyBase64);
		//aesInfo.put(multichainApp.AES_IV, ivBaseEncodedString);
		aesInfo.put(multichainApp.documentPrivateKey, encodedPrivKey);

	    
	}
	catch(Exception ex){
	    ex.printStackTrace();
	    throw ex;
	}
	return aesInfo;
    }
}