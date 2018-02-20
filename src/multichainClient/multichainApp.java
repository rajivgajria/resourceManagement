package multichainClient;

import java.util.Scanner;

public class multichainApp{
    public static final String dataPath = "/home/rajiv/workspace/blockchain/data/testchain";
    public static final String CourseProvider = "C";
    public static final String Employer = "E";
    public static final String Student = "S";
    public static final String Instructor = "I";
    public static final String Separator = "-";
    public static final String Document = "D";
    public static final String AES_KEY = "AES_KEY";
    public static final String AES_IV = "AES_IV";
    public static final String documentPrivateKey = "DocPriKey";
    public static final String documentID = "documentID";
    

    /*
     * This is the main method which starts the Blockchain Application
     * It has options like the following:
     * 1. Register (Register as a Course Provider, Student, Employer, Instructor )
     * 2. Store Certificate (Store the hash(data) of the PDF Certificate in the Blockchain)
     * 3. Access Certificate (Read the encrypted Certificate from the Blockchain)
     * 4. Provide Access to the Digital Certificate to the other user 
     * @param args
     */
    public static void main(String[] args){
	Operations op = new Operations();
	Scanner scanner = new Scanner(System.in);
	char userType;
	try{
	    //String filePath = "/home/rajiv/workspace/blockchain/data/testchain";
	    while (true){
		System.out.println("1. Register: ");
		System.out.println("2. Store certificate: ");
		System.out.println("3. Access certificate");
		System.out.println("4. Provide access to certificate: ");
		System.out.println("5. Check User: ");
		System.out.println("6. Exit");
		String taskType = scanner.nextLine();
		
		if (Integer.parseInt(taskType) == 1){
		    System.out.println("Are you a Course Provider / Employer / Student / Instructor (C/E/S/I)): ");

		    userType = scanner.nextLine().charAt(0);
		    op.registerUser(dataPath, userType);
		}

		if (Integer.parseInt(taskType) == 2){
		    System.out.println("Are you a Course Provider / Employer / Student / Instructor (C/E/S/I): ");

		    userType = scanner.nextLine().charAt(0);
		    op.storeCertificate(dataPath, userType);
		}
		if (Integer.parseInt(taskType) == 3){
		    // This will be for the Student and the Employer
		    System.out.println("Are you an Employer / Student (E/S): ");

		    userType = scanner.nextLine().charAt(0);
		    op.checkAccessCertificate();
		}
		if (Integer.parseInt(taskType) == 4){
		    // This will always be for the Student as of now
		    op.provideAccessCertificate();
		}
		if (Integer.parseInt(taskType) == 5){
		    System.out.println("Are you a Course Provider / Employer / Student / Instructor (C/E/S/I)): ");
		    userType = scanner.nextLine().charAt(0);
		    System.out.println("Enter User ID:");
		    String userID = scanner.nextLine();
		    op.checkUser(userType, userID);
		}
		if (Integer.parseInt(taskType) == 6){
		    return;
		}
	    }
	} catch (Exception ex){
	    ex.printStackTrace();
	}

	finally{
	    if (scanner != null){
		scanner.close();
	    }
	}

    }
}
