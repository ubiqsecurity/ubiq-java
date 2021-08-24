import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

import org.bouncycastle.crypto.InvalidCipherTextException;

import com.ubiqsecurity.UbiqCredentials;
import com.ubiqsecurity.UbiqFPEEncryptDecrypt;
import com.ubiqsecurity.UbiqFactory;

import com.ubiqsecurity.FFS;

import ubiqsecurity.fpe.Bn;

import java.math.BigInteger;

import java.nio.file.Path;
import java.nio.file.Paths;



public class UbiqSampleFPE {



    public static String printbytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ ");
        for (byte b : bytes) {
            sb.append(String.format("0x%02X ", b));
        }
        sb.append("]");
        return sb.toString();
    }

 
    public static void main(String[] args) throws Exception {
        File tweekFile= null;

        try {
            ExampleArgsFPE options = new ExampleArgsFPE();
            JCommander jCommander = JCommander.newBuilder().addObject(options).build();
            jCommander.setProgramName("Ubiq Security Example");
            jCommander.parse(args);
            
            
            // Sample calls: IMPORTANT, DO NOT USE DOUBLE QUOTES
            // $ java -cp './build/libs/ubiq-sample.jar:./build/deps/lib/*'  UbiqSampleFPE  -e '01$23-456-78-90' -c credentials -n 'FFS Name' -t tweekfile.txt
            // $ java -cp './build/libs/ubiq-sample.jar:./build/deps/lib/*'  UbiqSampleFPE  -d '00$01-LrI-6d-EA' -c credentials -n 'FFS Name' -t tweekfile.txt


            if (options.help) {
                System.out.println("\n************* Commandline Example *************");
                System.out.println("Encrypt:");
                System.out.println("java -cp './build/libs/ubiq-sample.jar:./build/deps/lib/*'  UbiqSampleFPE  -e '01$23-456-78-90' -c credentials -n 'FFS Name' -t abcdefghijk");
                System.out.println("Decrypt:");
                System.out.println("java -cp './build/libs/ubiq-sample.jar:./build/deps/lib/*'  UbiqSampleFPE  -d '00$01-LrI-6d-EA' -c credentials -n 'FFS Name' -t abcdefghijk");
                System.out.println("IMPORTANT, USE ONLY SINGLE QUOTES FOR COMMAND LINE OPTIONS");
                System.out.println("\n*************** Command Usage *****************\n");
                jCommander.usage();
                System.exit(0);
            }

            if (options.version) {
                System.out.println("ubiq-java 1.0.0");
                System.exit(0);
            }


            if ((options.encrypttext == null) && (options.decrypttext == null)) {
                throw new IllegalArgumentException("Encryption or Decrytion must be specified.");
            }
            if (options.encrypttext == options.decrypttext) {
                throw new IllegalArgumentException("Encryption or Decrytion have to be specified but not both.");
            }


            if (options.ffsname== null) {
                throw new IllegalArgumentException("ffsname must be specified.");
            }

            if (options.tweekFile!= null) {
                tweekFile = new File(options.tweekFile);
                if (!tweekFile.exists()) {
                    throw new IllegalArgumentException(String.format("Input file for tweek bytes does not exist: %s", options.tweekFile));
                }
            }

            UbiqCredentials ubiqCredentials;
            if (options.credentials == null) {
                // no file specified, so fall back to ENV vars and default host, if any
                ubiqCredentials = UbiqFactory.createCredentials(null, null, null, null);
            } else {
                // read credentials from caller-specified section of specified config file
                ubiqCredentials = UbiqFactory.readCredentialsFromFile(options.credentials, options.profile);
            }

                     
            byte[] tweekFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };
            
            if (options.tweekString!= null) {
                tweekFF1 = options.tweekString.getBytes();
                System.out.println("    commandline tweek bytes = " + printbytes(tweekFF1));
            } else if (options.tweekFile!= null) {
                tweekFF1 = Files.readAllBytes(Paths.get(options.tweekFile));
                System.out.println("    file tweek bytes = " + printbytes(tweekFF1));
            } else {
                System.out.println("    default tweek bytes = " + printbytes(tweekFF1));
            }
            
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 100)) {
            
                String FfsName = options.ffsname;
                                
                if (options.encrypttext!= null) {
                    String plainText = options.encrypttext;
                    
                    String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, FfsName, plainText, tweekFF1); 
                    System.out.println("ENCRYPTED cipher= " + cipher + "\n");
                
                } else if (options.decrypttext!= null) {
                    String cipher = options.decrypttext;
                    
                    String plaintext = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, FfsName, cipher, tweekFF1);
                    System.out.println("DECRYPTED plaintext= " + plaintext + "\n");
                }
                
 
 

                ////// TEST 2 - ENCRYPT AND DECRYPT
//                 final byte[] tweekFF3_1 = {
//                      (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
//                      (byte)0x00, (byte)0x00, (byte)0x00,
//                 };
//                 String plainText = "335-22-0188";
//                 System.out.println("\n@@@@@@@@@    simpleEncryptionFF3_1 PIN: " + plainText);
//                 String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "PIN", plainText, tweekFF3_1, "LDAP"); 
//                 System.out.println("ENCRYPTED    cipher= " + cipher);
// 
//                 System.out.println("\n@@@@@@@@@    simpleDecryptionFF3_1 PIN");
//                 String plaintext = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "PIN", cipher, tweekFF3_1, "LDAP");
//                 System.out.println("DECRYPTED    plaintext= " + plaintext);



            }


            System.exit(0);
        } catch (Exception ex) {
            System.out.println(String.format("Exception: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }
    }
    
  

 
    
}

class ExampleArgsFPE {
    @Parameter(
        names = { "--encrypttext", "-e" },
        description = "Set the field text value to encrypt and will return the encrypted cipher text.",
        arity = 1,
        required = false)
    String encrypttext;

    @Parameter(
        names = { "--decrypttext", "-d" },
        description = "Set the cipher text value to decrypt and will return the decrypted text.",
        arity = 1,
        required = false)
    String decrypttext;

    @Parameter(
        names = { "--ffsname", "-n" },
        description = "Set the ffs name, for example SSN.",
        arity = 1,
        required = true)
    String ffsname;

    @Parameter(
        names = { "--tweekfile", "-tf" },
        description = "Set input file name containing tweek bytes",
        arity = 1,
        required = false)
    String tweekFile;

    @Parameter(
        names = { "--tweek", "-t" },
        description = "Set alpha string to be used as tweek bytes",
        arity = 1,
        required = false)
    String tweekString;

    @Parameter(
        names = { "--help", "-h" },
        description = "Print app parameter summary",
        help = true)
    boolean help = false;

    @Parameter(
        names = { "--creds", "-c" },
        description = "Set the file name with the API credentials",
        arity = 1,
        required = false)
    String credentials = null;

    @Parameter(
        names = { "--profile", "-P" },
        description = "Identify the profile within the credentials file",
        arity = 1,
        required = false)
    String profile = "default";

    @Parameter(
        names = { "--version", "-V" },
        description = "Show program's version number and exit",
        help = true)
    boolean version = false;
}
