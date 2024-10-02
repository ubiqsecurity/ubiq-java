import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.nio.file.Files;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.bouncycastle.crypto.InvalidCipherTextException;
import com.ubiqsecurity.UbiqCredentials;
import com.ubiqsecurity.UbiqStructuredEncryptDecrypt;
import com.ubiqsecurity.UbiqFactory;


/**
 * Sample command line application demonstrates how to call the Ubiq Structured
 * encrypt and decrypt functions.
 */
public class UbiqSampleStructured {
    public static void main(String[] args) throws Exception {
        try {
            ExampleArgsStructured options = new ExampleArgsStructured();
            JCommander jCommander = JCommander.newBuilder().addObject(options).build();
            jCommander.setProgramName("Ubiq Security Example");
            jCommander.parse(args);


            // Sample calls: IMPORTANT, DO NOT USE DOUBLE QUOTES
            if (options.help) {
                System.out.println("\n************* Commandline Example *************");
                System.out.println("Encrypt:");
                System.out.println("java -cp './build/libs/ubiq-sample.jar:./build/deps/lib/*'  UbiqSampleStructured  -e '123-45-6789' -c credentials -n 'ALPHANUM_SSN' -s");
                System.out.println("Decrypt:");
                System.out.println("java -cp './build/libs/ubiq-sample.jar:./build/deps/lib/*'  UbiqSampleStructured  -d 'W$+-qF-oMMV' -c credentials -n 'ALPHANUM_SSN' -s");
                System.out.println("IMPORTANT, USE ONLY SINGLE QUOTES FOR COMMAND LINE OPTIONS");
                System.out.println("\n*************** Command Usage *****************\n");
                jCommander.usage();
                System.exit(0);
            }

            if (options.version) {
                System.out.println("UbiqSampleStructured 1.0.0");
                System.exit(0);
            }

            if ((options.encrypttext == null) && (options.decrypttext == null)) {
                throw new IllegalArgumentException("Encryption or Decryption must be specified.");
            }
            if (options.encrypttext == options.decrypttext) {
                throw new IllegalArgumentException("Encryption or Decryption have to be specified but not both.");
            }

            if (options.datasetName == null) {
                throw new IllegalArgumentException("dataset name must be specified.");
            }

            UbiqCredentials ubiqCredentials = null;
            try {
              if (options.credentials == null) {
                  // no file specified, so fall back to ENV vars and default host, if any
                  ubiqCredentials = UbiqFactory.defaultCredentials();
              } else {
                  // read credentials from caller-specified section of specified config file
                  ubiqCredentials = UbiqFactory.readCredentialsFromFile(options.credentials, options.profile);
              }
            } catch (Exception ex) {
              System.out.println(String.format("Unable to set credentials\nException: %s", ex.getMessage()));
              System.exit(1);
            }

            if (ubiqCredentials == null || ubiqCredentials.getAccessKeyId() == null)  {
              System.out.println(String.format("Unable to set credentials"));
              System.exit(1);
            }

            String datasetName = options.datasetName;
            byte[] tweakFF1 = null;

            if (options.tweakString!= null) {
              tweakFF1 = Base64.getDecoder().decode(options.tweakString);
            }

            // demonstrate setting up the UbiqStructuredEncryptDecrypt manually so that it could be used
            // multiple times whenever many operations are to be performed in a session.

            try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

                if (options.encrypttext!= null) {
                    String plainText = options.encrypttext;

                    String cipher = ubiqEncryptDecrypt.encrypt(datasetName, plainText, tweakFF1);
                    System.out.println("ENCRYPTED cipher= " + cipher + "\n");

                } else if (options.decrypttext!= null) {
                    String cipher = options.decrypttext;

                    String plaintext = ubiqEncryptDecrypt.decrypt(datasetName, cipher, tweakFF1);
                    System.out.println("DECRYPTED plaintext= " + plaintext + "\n");
                }

            }

            System.exit(0);
        } catch (Exception ex) {
            System.out.println(String.format("Exception: %s", ex.getMessage()));
            System.exit(1);
        }
    }
}

class ExampleArgsStructured {
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
        names = { "--dataset", "-n" },
        description = "Set the dataset name, for example SSN.",
        arity = 1,
        required = true)
    String datasetName;

    @Parameter(
        names = { "--tweak", "-t" },
        description = "Tweak encoded as a base64 string",
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
