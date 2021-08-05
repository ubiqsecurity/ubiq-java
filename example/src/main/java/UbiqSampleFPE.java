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





public class UbiqSampleFPE {
    public static void main(String[] args) throws Exception {

        try {
            ExampleArgsFPE options = new ExampleArgsFPE();
            JCommander jCommander = JCommander.newBuilder().addObject(options).build();
            jCommander.setProgramName("Ubiq Security Example");
            jCommander.parse(args);
            
            

            if (options.help) {
                jCommander.usage();
                System.exit(0);
            }

            if (options.version) {
                System.out.println("ubiq-java 1.0.0");
                System.exit(0);
            }

            if (options.simple == options.piecewise) {
                throw new IllegalArgumentException("simple or piecewise API option need to be specified but not both");
            }

            if (options.encrypt == options.decrypt) {
                throw new IllegalArgumentException("Encryption or Decrytion have to be specified but not both");
            }

            File inputFile = new File(options.inputFile);
            if (!inputFile.exists()) {
                throw new IllegalArgumentException(String.format("Input file does not exist: %s", options.inputFile));
            }



            UbiqCredentials ubiqCredentials;
            if (options.credentials == null) {
                // no file specified, so fall back to ENV vars and default host, if any
                ubiqCredentials = UbiqFactory.createCredentials(null, null, null, null);
            } else {
                // read credentials from caller-specified section of specified config file
                ubiqCredentials = UbiqFactory.readCredentialsFromFile(options.credentials, options.profile);
            }

            // check input file size - we already know it exists
            {
                long maxSimpleSize = 50 * 0x100000; // 50MB
                if (Boolean.TRUE.equals(options.simple) && (inputFile.length() > maxSimpleSize)) {
                    System.out.println("NOTE: This is only for demonstration purposes and is designed to work on memory");
                    System.out.println("      constrained devices.  Therefore, this sample application will switch to");
                    System.out.println(String.format("      the piecewise APIs for files larger than %d bytes in order to reduce", maxSimpleSize));
                    System.out.println("      excessive resource usages on resource constrained IoT devices");
                    options.simple = false;
                    options.piecewise = true;
                }
            }
/*
            if (Boolean.TRUE.equals(options.simple)) {
                if (Boolean.TRUE.equals(options.encrypt)) {
                    simpleEncryption(options.inputFile, options.outputFile, ubiqCredentials);
                } else {
                    simpleDecryption(options.inputFile, options.outputFile, ubiqCredentials);
                }
            } else {
                if (Boolean.TRUE.equals(options.encrypt)) {
                    piecewiseEncryption(options.inputFile, options.outputFile, ubiqCredentials);
                } else {
                    piecewiseDecryption(options.inputFile, options.outputFile, ubiqCredentials);
                }
            }
*/



 


            ////// TEST 1 - ENCRYPT AND DECRYPT
            // HARDcODE credentials for testing/dev purposes
//             ubiqCredentials = UbiqFactory.createCredentials(
//                     "0cxsgl9sL2QLGlBpm6D3s6KG",
//                     "ZBkJQWe8Ylz6TBa3avYkc4zUb5tEk62wsya7wBZM8aDC",
//                     "RzF9gvqFp7H0a1pzRpLBfBavQSNyqJJJ0yWrwWtWGvIS",
//                     "https://stg.koala.ubiqsecurity.com");
                    
            ubiqCredentials = UbiqFactory.createCredentials(
                    "aox5ZRptLg8B758xllfEFsNG",
                    "fhxmkk4lB/l6bnuKUxT2gYpdMoiSk+1AwUUIyD/ghQPu",
                    "YvNtl2+G3v5d3OeIz5ORuut8wZgsUChcTHBy3Uew9NiR",
                    "http://localhost:8443");
                    
                    
            final byte[] tweekFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 1)) {
            
                System.out.println("\n@@@@@@@@@    simpleEncryptionFF1 SSN");
                //String plainText = "0123456789";
                String plainText = "123-45-6789";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "SSN", plainText, tweekFF1, "LDAP"); 
                System.out.println("    plainText= " + plainText + "    cipher= " + cipher);

                System.out.println("\n@@@@@@@@@    simpleDecryptionFF1 SSN");
                String plaintext = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "SSN", cipher, tweekFF1, "LDAP");
                System.out.println("    plaintext= " + plaintext);



                ////// TEST 2 - ENCRYPT AND DECRYPT
                final byte[] tweekFF3_1 = {
                     (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                     (byte)0x00, (byte)0x00, (byte)0x00,
                };
                System.out.println("\n@@@@@@@@@    simpleEncryptionFF3_1 PIN");
                plainText = "890121234567890000";
                cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "PIN", plainText, tweekFF3_1, "LDAP"); 
                System.out.println("    plainText= " + plainText + "    cipher= " + cipher);

                System.out.println("\n@@@@@@@@@    simpleDecryptionFF3_1 PIN");
                plaintext = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "PIN", cipher, tweekFF3_1, "LDAP");
                System.out.println("    plaintext= " + plaintext);



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
        names = { "--encrypt", "-e" },
        description = "Encrypt the contents of the input file and write the results to output file",
        required = false)
    Boolean encrypt = null;

    @Parameter(
        names = { "--decrypt", "-d" },
        description = "Decrypt the contents of the input file and write the results to output file",
        required = false)
    Boolean decrypt = null;

    @Parameter(
        names = { "--simple", "-s" },
        description = "Use the simple encryption / decryption interfaces",
        required = false)
    Boolean simple = null;

    @Parameter(
        names = { "--piecewise", "-p" },
        description = "Use the piecewise encryption / decryption interfaces",
        required = false)
    Boolean piecewise = null;

    @Parameter(
        names = { "--in", "-i" },
        description = "Set input file name",
        arity = 1,
        required = true)
    String inputFile;

    @Parameter(
        names = { "--out", "-o" },
        description = "Set output file name",
        arity = 1,
        required = true)
    String outputFile;

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
