import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.nio.file.Files;
import java.time.OffsetDateTime;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.bouncycastle.crypto.InvalidCipherTextException;
import com.ubiqsecurity.UbiqCredentials;
import com.ubiqsecurity.UbiqConfiguration;
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
            if ((options.search) && (options.encrypttext == null)) {
                throw new IllegalArgumentException("Search option is only allowed with Encryption.");
            }

            if (options.datasetName == null) {
                throw new IllegalArgumentException("dataset name must be specified.");
            }

            if (options.integer32 && (options.integer64 || options.date || options.datetime)) {
              throw new IllegalArgumentException("Integer32 can not be used with integer64, date, or datetime flags.");
            }

            if (options.integer64 && (options.date || options.datetime)) {
              throw new IllegalArgumentException("Integer64 can not be used with date or datetime flags.");
            }

            if (options.date && options.datetime) {
              throw new IllegalArgumentException("Date can not be used with datetime flags.");
            }

            UbiqCredentials ubiqCredentials = null;
            UbiqConfiguration ubiqConfig = null;

            try {
              if (options.configuration == null) {
                // no file specified, so fall back to ENV vars and default host, if any
                ubiqConfig = UbiqFactory.defaultConfiguration();
              } else {
                  // read credentials from caller-specified section of specified config file
                  ubiqConfig = UbiqFactory.readConfigurationFromFile(options.configuration);
              }
            } catch (Exception ex) {
              System.out.println(String.format("Unable to set configuration\nException: %s", ex.getMessage()));
              System.exit(1);
            }

            try {
              if (options.credentials == null) {
                  // no file specified, so fall back to ENV vars and default host, if any
                  System.out.println(String.format("No explicit credentials provided – using default credentials"));
                  ubiqCredentials = UbiqFactory.defaultCredentials();
              } else {
                  System.out.println(String.format("Loading credentials from %s, profile %s",options.credentials, options.profile));
                  // read credentials from caller-specified section of specified config file
                  ubiqCredentials = UbiqFactory.readCredentialsFromFile(options.credentials, options.profile);
              }
            } catch (Exception ex) {
              System.out.println(String.format("Unable to set credentials\nException: %s", ex.getMessage()));
              System.exit(1);
            }
            if (ubiqConfig != null) {
              ubiqCredentials.init(ubiqConfig);
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

            try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials, ubiqConfig)) {

                if (options.encrypttext!= null) {
                    String plainText = options.encrypttext;
                    if (options.search) {
                      if (options.integer32) {
                        int pt_i = Integer.valueOf(options.encrypttext);
                        int [] ct = ubiqEncryptDecrypt.encryptIntForSearch(datasetName, pt_i, tweakFF1);
                        System.out.println("EncryptIntForSearch results:");
                        for (int s : ct) {
                          System.out.println("\t" + s);
                        }
                      } else if (options.integer64) {
                        long pt_l = Long.valueOf(options.encrypttext);
                        long [] ct = ubiqEncryptDecrypt.encryptLongForSearch(datasetName, pt_l, tweakFF1);
                        System.out.println("EncryptLongForSearch results:");
                        for (long s : ct) {
                          System.out.println("\t" + s);
                        }
                      } else if (options.datetime) {
                        OffsetDateTime pt_dt = OffsetDateTime.parse(options.encrypttext);
                        OffsetDateTime [] ct = ubiqEncryptDecrypt.encryptDateTimeForSearch(datasetName, pt_dt, tweakFF1);
                        System.out.println("EncryptDateTimeForSearch results:");
                        for (OffsetDateTime s : ct) {
                          System.out.println("\t" + s);
                        }
                      } else if (options.date) {
                        OffsetDateTime pt_d = OffsetDateTime.parse(options.encrypttext);
                        OffsetDateTime [] ct = ubiqEncryptDecrypt.encryptDateForSearch(datasetName, pt_d, tweakFF1);
                        System.out.println("EncryptDateForSearch results:");
                        for (OffsetDateTime s : ct) {
                          System.out.println("\t" + s);
                        }
                      } else {
                        String [] cipher = ubiqEncryptDecrypt.encryptForSearch(datasetName, plainText, tweakFF1);
                        System.out.println("EncryptForSearch results:");
                        for (String s : cipher) {
                          System.out.println("\t" + s);
                        }
                      }
                    } else {
                      if (options.integer32) {
                        int pt_i = Integer.valueOf(options.encrypttext);
                        int ct_i = ubiqEncryptDecrypt.encryptInt(datasetName, pt_i, tweakFF1);
                        System.out.println("Encrypted integer= " + ct_i);
                      } else if (options.integer64) {
                        long pt_l = Long.valueOf(options.encrypttext);
                        long ct_l = ubiqEncryptDecrypt.encryptLong(datasetName, pt_l, tweakFF1);
                        System.out.println("Encrypted long = " + ct_l);
                      } else if (options.datetime) {
                        OffsetDateTime pt_dt = OffsetDateTime.parse(options.encrypttext);
                        OffsetDateTime ct_dt = ubiqEncryptDecrypt.encryptDateTime(datasetName, pt_dt, tweakFF1);
                        System.out.println("Encrypted datetime = " + ct_dt);
                      } else if (options.date) {
                        OffsetDateTime pt_d = OffsetDateTime.parse(options.encrypttext);
                        OffsetDateTime ct_d = ubiqEncryptDecrypt.encryptDate(datasetName, pt_d, tweakFF1);
                        System.out.println("Encrypted date = " + ct_d);
                      } else {
                        String cipher = ubiqEncryptDecrypt.encrypt(datasetName, plainText, tweakFF1);
                        System.out.println("ENCRYPTED cipher= " + cipher + "\n");
                      }
                    }


                } else if (options.decrypttext!= null) {
                    String cipher = options.decrypttext;

                      if (options.integer32) {
                        int ct_i = Integer.valueOf(cipher);
                        int pt_i = ubiqEncryptDecrypt.decryptInt(datasetName, ct_i, tweakFF1);
                        System.out.println("Decrypted integer= " + pt_i);
                      } else if (options.integer64) {
                        long ct_l = Long.valueOf(cipher);
                        long pt_l = ubiqEncryptDecrypt.decryptLong(datasetName, ct_l, tweakFF1);
                        System.out.println("Decrypted long = " + pt_l);
                      } else if (options.datetime) {
                        OffsetDateTime ct_dt = OffsetDateTime.parse(cipher);
                        OffsetDateTime pt_dt = ubiqEncryptDecrypt.decryptDateTime(datasetName, ct_dt, tweakFF1);
                        System.out.println("Decrypted datetime = " + pt_dt);
                      } else if (options.date) {
                        OffsetDateTime ct_d = OffsetDateTime.parse(cipher);
                        OffsetDateTime pt_d = ubiqEncryptDecrypt.decryptDate(datasetName, ct_d, tweakFF1);
                        System.out.println("Decrypted date = " + pt_d);
                      } else {
                        String plaintext = ubiqEncryptDecrypt.decrypt(datasetName, cipher, tweakFF1);
                        System.out.println("DECRYPTED plaintext= " + plaintext + "\n");
                      }
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
      names = { "--config", "-g" },
      description = "Set the file name for the configuration file",
      arity = 1,
      required = false)
    String configuration = null;

    @Parameter(
        names = { "--version", "-V" },
        description = "Show program's version number and exit",
        help = true)
    boolean version = false;

    @Parameter(
        names = { "--datetime" },
        description = "Treat input as a datetime",
        help = true)
    boolean datetime = false;

    @Parameter(
        names = { "--date" },
        description = "Treat input as a date",
        help = true)
    boolean date = false;

    @Parameter(
        names = { "--integer32" },
        description = "Treat input as an integer 32",
        help = true)
    boolean integer32 = false;

    @Parameter(
        names = { "--integer64" },
        description = "Treat input as an integer 64",
        help = true)
    boolean integer64 = false;

    @Parameter(
        names = { "--search", "-s" },
        description = "Perform the EncryptForSearch.  Only compatibile with the -e option",
        required = false)
    Boolean search = false;

}
