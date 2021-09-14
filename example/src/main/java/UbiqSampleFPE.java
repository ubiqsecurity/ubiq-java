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
                System.out.println("java -cp './build/libs/ubiq-sample.jar:./build/deps/lib/*'  UbiqSampleFPE  -e '123-45-6789' -c credentials -n 'ALPHANUM_SSN'");
                System.out.println("Decrypt:");
                System.out.println("java -cp './build/libs/ubiq-sample.jar:./build/deps/lib/*'  UbiqSampleFPE  -d 'W$+-qF-oMMV' -c credentials -n 'ALPHANUM_SSN'");
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

            UbiqCredentials ubiqCredentials;
            if (options.credentials == null) {
                // no file specified, so fall back to ENV vars and default host, if any
                ubiqCredentials = UbiqFactory.createCredentials(null, null, null, null);
            } else {
                // read credentials from caller-specified section of specified config file
                ubiqCredentials = UbiqFactory.readCredentialsFromFile(options.credentials, options.profile);
            }

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
            
                String FfsName = options.ffsname;
                                
                if (options.encrypttext!= null) {
                    String plainText = options.encrypttext;
                    
                    String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, FfsName, plainText, tweakFF1); 
                    System.out.println("ENCRYPTED cipher= " + cipher + "\n");
                
                } else if (options.decrypttext!= null) {
                    String cipher = options.decrypttext;
                    
                    String plaintext = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, FfsName, cipher, tweakFF1);
                    System.out.println("DECRYPTED plaintext= " + plaintext + "\n");
                }

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
