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
import com.ubiqsecurity.UbiqConfiguration;
import com.ubiqsecurity.UbiqDecrypt;
import com.ubiqsecurity.UbiqEncrypt;
import com.ubiqsecurity.UbiqFactory;
import com.ubiqsecurity.UbiqUnstructuredEncryptSession;
import com.ubiqsecurity.UbiqUnstructuredDecryptSession;

public class UbiqSample {
    public static void main(String[] args) throws Exception {

        try {
            ExampleArgs options = new ExampleArgs();
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
                throw new IllegalArgumentException("Encryption or Decryption have to be specified but not both");
            }

            File inputFile = new File(options.inputFile);
            if (!inputFile.exists()) {
                throw new IllegalArgumentException(String.format("Input file does not exist: %s", options.inputFile));
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
                  ubiqCredentials = UbiqFactory.defaultCredentials();
              } else {
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

            if (Boolean.TRUE.equals(options.simple)) {
                if (Boolean.TRUE.equals(options.encrypt)) {
                    simpleEncryption(options.inputFile, options.outputFile, ubiqCredentials, ubiqConfig);
                } else {
                    simpleDecryption(options.inputFile, options.outputFile, ubiqCredentials, ubiqConfig);
                }
            } else {
                if (Boolean.TRUE.equals(options.encrypt)) {
                    piecewiseEncryption(options.inputFile, options.outputFile, ubiqCredentials, ubiqConfig);
                } else {
                    piecewiseDecryption(options.inputFile, options.outputFile, ubiqCredentials, ubiqConfig);
                }
            }

            System.exit(0);
        } catch (Exception ex) {
            System.out.println(String.format("Exception: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private static void simpleEncryption(String inFile, String outFile, UbiqCredentials ubiqCredentials, UbiqConfiguration ubiqConfiguration)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        byte[] plainBytes = Files.readAllBytes(new File(inFile).toPath());
        byte[] cipherBytes = UbiqEncrypt.encrypt(ubiqCredentials, plainBytes,ubiqConfiguration);
        Files.write(new File(outFile).toPath(), cipherBytes);
    }

    private static void simpleDecryption(String inFile, String outFile, UbiqCredentials ubiqCredentials, UbiqConfiguration ubiqConfiguration)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        byte[] cipherBytes = Files.readAllBytes(new File(inFile).toPath());
        byte[] plainBytes = UbiqDecrypt.decrypt(ubiqCredentials, cipherBytes, ubiqConfiguration);
        Files.write(new File(outFile).toPath(), plainBytes);
    }

    private static void piecewiseEncryption(String inFile, String outFile, UbiqCredentials ubiqCredentials, UbiqConfiguration ubiqConfiguration)
            throws IOException, IllegalStateException, InvalidCipherTextException {
        try (FileInputStream plainStream = new FileInputStream(inFile)) {
            try (FileOutputStream cipherStream = new FileOutputStream(outFile)) {
                try (UbiqEncrypt ubiqEncrypt = new UbiqEncrypt(ubiqCredentials, 1, ubiqConfiguration)) {
                    UbiqUnstructuredEncryptSession encryptSession = ubiqEncrypt.initSession();
                    byte[] cipherBytes = ubiqEncrypt.begin(encryptSession);
                    cipherStream.write(cipherBytes);

                    byte[] plainBytes = new byte[0x20000];
                    int bytesRead = 0;
                    while ((bytesRead = plainStream.read(plainBytes, 0, plainBytes.length)) > 0) {
                        cipherBytes = ubiqEncrypt.update(encryptSession, plainBytes, 0, bytesRead);
                        cipherStream.write(cipherBytes);
                    }

                    cipherBytes = ubiqEncrypt.end(encryptSession);
                    cipherStream.write(cipherBytes);
                }
            }
        }
    }

    private static void piecewiseDecryption(String inFile, String outFile, UbiqCredentials ubiqCredentials, UbiqConfiguration ubiqConfiguration)
            throws FileNotFoundException, IOException, IllegalStateException, InvalidCipherTextException {
        try (FileInputStream cipherStream = new FileInputStream(inFile)) {
            try (FileOutputStream plainStream = new FileOutputStream(outFile)) {
                try (UbiqDecrypt ubiqDecrypt = new UbiqDecrypt(ubiqCredentials, ubiqConfiguration)) {
                    UbiqUnstructuredDecryptSession decryptSession = ubiqDecrypt.initSession();
                    byte[] plainBytes = ubiqDecrypt.begin(decryptSession);
                    plainStream.write(plainBytes);

                    byte[] cipherBytes = new byte[0x20000];
                    int bytesRead = 0;
                    while ((bytesRead = cipherStream.read(cipherBytes, 0, cipherBytes.length)) > 0) {
                        plainBytes = ubiqDecrypt.update(decryptSession, cipherBytes, 0, bytesRead);
                        plainStream.write(plainBytes);
                    }

                    plainBytes = ubiqDecrypt.end(decryptSession);
                    plainStream.write(plainBytes);
                }
            }
        }
    }
}

class ExampleArgs {
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
}
