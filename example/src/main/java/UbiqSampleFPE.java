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


/**
 * Sample command line application demonstrates how to call the Ubiq FPE
 * encrypt and decrypt functions.
 */
public class UbiqSampleFPE {
    public static void main(String[] args) throws Exception {
        try {
            ExampleArgsFPE options = new ExampleArgsFPE();
            JCommander jCommander = JCommander.newBuilder().addObject(options).build();
            jCommander.setProgramName("Ubiq Security Example");
            jCommander.parse(args);
            
            
            // Sample calls: IMPORTANT, DO NOT USE DOUBLE QUOTES
            if (options.help) {
                System.out.println("\n************* Commandline Example *************");
                System.out.println("Encrypt:");
                System.out.println("java -cp './build/libs/ubiq-sample.jar:./build/deps/lib/*'  UbiqSampleFPE  -e '123-45-6789' -c credentials -n 'ALPHANUM_SSN' -s");
                System.out.println("Decrypt:");
                System.out.println("java -cp './build/libs/ubiq-sample.jar:./build/deps/lib/*'  UbiqSampleFPE  -d 'W$+-qF-oMMV' -c credentials -n 'ALPHANUM_SSN' -s");
                System.out.println("IMPORTANT, USE ONLY SINGLE QUOTES FOR COMMAND LINE OPTIONS");
                System.out.println("\n*************** Command Usage *****************\n");
                jCommander.usage();
                System.exit(0);
            }

            if (options.version) {
                System.out.println("ubiq-java 1.0.0");
                System.exit(0);
            }
            
            if ((options.simple!= null) && (options.bulk!= null)) {
                throw new IllegalArgumentException("Cannot select both simple and bulk API options.");
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

            UbiqCredentials ubiqCredentials;
            if (options.credentials == null) {
                // no file specified, so fall back to ENV vars and default host, if any
                ubiqCredentials = UbiqFactory.createCredentials(null, null, null, null);
            } else {
                // read credentials from caller-specified section of specified config file
                ubiqCredentials = UbiqFactory.readCredentialsFromFile(options.credentials, options.profile);
            }

            
            String FfsName = options.ffsname;
            
            if (Boolean.TRUE.equals(options.bulk)) {
                // demonstrate setting up the UbiqFPEEncryptDecrypt manually so that it could be used
                // multiple times whenever many operations are to be performed in a session.
                
                // default tweak in case the FFS model allows for external tweak insertion          
                byte[] tweakFF1 = {
                    (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                    (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                    (byte)0x31, (byte)0x30,
                };
                if (options.tweakString!= null) {
                    tweakFF1 = options.tweakString.getBytes();
                } 

                try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                                
                    if (options.encrypttext!= null) {
                        String plainText = options.encrypttext;
                    
                        String cipher = ubiqEncryptDecrypt.encryptFPE(FfsName, plainText, tweakFF1); 
                        System.out.println("ENCRYPTED cipher= " + cipher + "\n");
                
                    } else if (options.decrypttext!= null) {
                        String cipher = options.decrypttext;
                    
                        String plaintext = ubiqEncryptDecrypt.decryptFPE(FfsName, cipher, tweakFF1);
                        System.out.println("DECRYPTED plaintext= " + plaintext + "\n");
                    }

                }
            } else {
                // demonstrates a simpler single-shot encrypt/decrypt and default tweak
                if (options.encrypttext!= null) {
                    String plainText = options.encrypttext;
                
                    simpleEncryption(FfsName, plainText, ubiqCredentials);
            
                } else if (options.decrypttext!= null) {
                    String cipher = options.decrypttext;
                
                    simpleDecryption(FfsName, cipher, ubiqCredentials);
                }
            }
            

            System.exit(0);
        } catch (Exception ex) {
            System.out.println(String.format("Exception: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }
    }
    

    /**
     * Demonstrates case when you only need to perform a single operation and have
     * the function create the UbiqFPEEncryptDecrypt for you for each call.
     *
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     * @param plainText   the text you wish to encrypt
     * @param ubiqCredentials   used to specify the API key credentials of the user
     *
     */        
    private static void simpleEncryption(String FfsName, String plainText, UbiqCredentials ubiqCredentials)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
            String cipher = ubiqEncryptDecrypt.encryptFPE(FfsName, plainText, null); 
            System.out.println("ENCRYPTED cipher= " + cipher + "\n");
        }
    }

    /**
     * Demonstrates case when you only need to perform a single operation and have
     * the function create the UbiqFPEEncryptDecrypt for you for each call.
     *
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     * @param cipher   the text you wish to decrypt
     * @param ubiqCredentials   used to specify the API key credentials of the user
     *
     */            
    private static void simpleDecryption(String FfsName, String cipher, UbiqCredentials ubiqCredentials)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
            String plainText = ubiqEncryptDecrypt.decryptFPE(FfsName, cipher, null); 
            System.out.println("DECRYPTED plainText= " + plainText + "\n");
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
        names = { "--simple", "-s" },
        description = "Use the simple encryption / decryption interfaces",
        required = false)
    Boolean simple = null;

    @Parameter(
        names = { "--bulk", "-b" },
        description = "Use the bulk encryption / decryption interfaces",
        required = false)
    Boolean bulk = null;

    @Parameter(
        names = { "--ffsname", "-n" },
        description = "Set the ffs name, for example SSN.",
        arity = 1,
        required = true)
    String ffsname;

    @Parameter(
        names = { "--tweak", "-t" },
        description = "Set alpha string to be used as tweak bytes",
        arity = 1,
        required = false)
    String tweakString;

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
