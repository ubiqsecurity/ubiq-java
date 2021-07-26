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
//import com.ubiqsecurity.UbiqDecrypt;
//import com.ubiqsecurity.UbiqEncrypt;
import com.ubiqsecurity.UbiqFPEDecrypt;
import com.ubiqsecurity.UbiqFPEEncrypt;
import com.ubiqsecurity.UbiqFactory;

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



 




////// TESTING
// BigInteger r1 = Bn.__bigint_set_str("100", "0123456789");
// System.out.println("@@@@@@@@@    r1= " + r1); 
// 
// 
// System.out.println("\n@@@@@@@@@    Testing FF1"); 
// String output = UbiqFPEEncrypt.encryptFF1("0123456789");
// String decrypt = UbiqFPEDecrypt.decryptFF1(output);
// 
// System.out.println("\n@@@@@@@@@    Testing FF3_1");
// output = UbiqFPEEncrypt.encryptFF3_1("890121234567890000");
// decrypt = UbiqFPEDecrypt.decryptFF3_1(output);


            System.out.println("\n@@@@@@@@@    simpleEncryptionFF1");
            String cipher = simpleEncryptionFF1("0123456789", ubiqCredentials);
            System.out.println("    cipher= " + cipher);

            System.out.println("\n@@@@@@@@@    simpleDecryptionFF1");
            String plaintext = simpleDecryptionFF1(cipher, ubiqCredentials);
            System.out.println("    plaintext= " + plaintext);



            System.out.println("\n@@@@@@@@@    simpleEncryptionFF3_1");
            cipher = simpleEncryptionFF3_1("890121234567890000", ubiqCredentials);
            System.out.println("    cipher= " + cipher);

            System.out.println("\n@@@@@@@@@    simpleDecryptionFF3_1");
            plaintext = simpleDecryptionFF3_1(cipher, ubiqCredentials);
            System.out.println("    plaintext= " + plaintext);






            System.exit(0);
        } catch (Exception ex) {
            System.out.println(String.format("Exception: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }
    }
    
    
    
    
    
    
    private static String simpleEncryptionFF1(String PlainText, UbiqCredentials ubiqCredentials)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        
        // tweek
        final byte[] tweek = {
            (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
            (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
            (byte)0x31, (byte)0x30,
        };
        
        final int radix= 10;
        
        String cipher = UbiqFPEEncrypt.encryptFF1(ubiqCredentials, tweek, radix, PlainText);
        
        return cipher;
    }    
    
    
    private static String simpleDecryptionFF1(String CipherText, UbiqCredentials ubiqCredentials)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        
        // tweek
        final byte[] tweek = {
            (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
            (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
            (byte)0x31, (byte)0x30,
        };
        
        final int radix= 10;
        
        String plaintext = UbiqFPEDecrypt.decryptFF1(ubiqCredentials, tweek, radix, CipherText);
        
        return plaintext;
    }    


    
     private static String simpleEncryptionFF3_1(String PlainText, UbiqCredentials ubiqCredentials)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        
        // tweek
        final byte[] tweek = {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00,
        };
        
        final int radix= 10;
        
        String cipher = UbiqFPEEncrypt.encryptFF3_1(ubiqCredentials, tweek, radix, PlainText);
        
        return cipher;
    }     
    
    
    private static String simpleDecryptionFF3_1(String PlainText, UbiqCredentials ubiqCredentials)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        
        // tweek
        final byte[] tweek = {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00,
        };
        
        final int radix= 10;
        
        String cipher = UbiqFPEDecrypt.decryptFF3_1(ubiqCredentials, tweek, radix, PlainText);
        
        return cipher;
    }    
    
    
    
    

/*
    private static void simpleEncryption(String inFile, String outFile, UbiqCredentials ubiqCredentials)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        byte[] plainBytes = Files.readAllBytes(new File(inFile).toPath());
        byte[] cipherBytes = UbiqFPEEncrypt.encrypt(ubiqCredentials, plainBytes);
        Files.write(new File(outFile).toPath(), cipherBytes);
    }

    private static void simpleDecryption(String inFile, String outFile, UbiqCredentials ubiqCredentials)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        byte[] cipherBytes = Files.readAllBytes(new File(inFile).toPath());
        byte[] plainBytes = UbiqFPEDecrypt.decrypt(ubiqCredentials, cipherBytes);
        Files.write(new File(outFile).toPath(), plainBytes);
    }

    private static void piecewiseEncryption(String inFile, String outFile, UbiqCredentials ubiqCredentials)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        try (FileInputStream plainStream = new FileInputStream(inFile)) {
            try (FileOutputStream cipherStream = new FileOutputStream(outFile)) {
                try (UbiqFPEEncrypt ubiqEncrypt = new UbiqFPEEncrypt(ubiqCredentials, 1)) {
                    byte[] cipherBytes = ubiqEncrypt.begin();
                    cipherStream.write(cipherBytes);

                    var plainBytes = new byte[0x20000];
                    int bytesRead = 0;
                    while ((bytesRead = plainStream.read(plainBytes, 0, plainBytes.length)) > 0) {
                        cipherBytes = ubiqEncrypt.update(plainBytes, 0, bytesRead);
                        cipherStream.write(cipherBytes);
                    }

                    cipherBytes = ubiqEncrypt.end();
                    cipherStream.write(cipherBytes);
                }
            }
        }
    }

    private static void piecewiseDecryption(String inFile, String outFile, UbiqCredentials ubiqCredentials)
            throws FileNotFoundException, IOException, IllegalStateException, InvalidCipherTextException {
        try (FileInputStream cipherStream = new FileInputStream(inFile)) {
            try (FileOutputStream plainStream = new FileOutputStream(outFile)) {
                try (UbiqFPEDecrypt ubiqDecrypt = new UbiqFPEDecrypt(ubiqCredentials)) {
                    byte[] plainBytes = ubiqDecrypt.begin();
                    plainStream.write(plainBytes);

                    var cipherBytes = new byte[0x20000];
                    int bytesRead = 0;
                    while ((bytesRead = cipherStream.read(cipherBytes, 0, cipherBytes.length)) > 0) {
                        plainBytes = ubiqDecrypt.update(cipherBytes, 0, bytesRead);
                        plainStream.write(plainBytes);
                    }

                    plainBytes = ubiqDecrypt.end();
                    plainStream.write(plainBytes);
                }
            }
        }
    }
*/    
    
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
