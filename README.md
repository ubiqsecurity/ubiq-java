## Ubiq Security Java Library

The Ubiq Security Java library provides convenient interaction with the Ubiq Security Platform API from applications written in the Java language.  It includes a pre-defined set of classes that will provide simple interfaces to encrypt and decrypt data.

This library also incorporates format preserving encryption (FPE), available as an optional add-on to your user account. FPE allows encrypting so that the output cipher text is in the same format as the original plaintext. This includes preserving special characters and control over what characters are permitted in the cipher text. For example, consider encrypting a social security number '123-45-6789'. The cipher text will maintain the dashes and look something like: 'W$+-qF-oMMV'.
Additionally, Ubiq supports embedded format preserving encryption (eFPE) providing the ability to store additional meta data within the cipher text.

## Documentation

See the [Java API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

### Requirements
Java 11 or later

### Gradle Users

Add this dependency to your project's build file:

```groovy
implementation group: 'com.ubiqsecurity', name: 'ubiqsecurity', version: 'latest.release'
```

### Maven users
Add this dependency to your project's POM:
where X.Y.Z represents the appropriate version number.

```xml
<dependency>
  <groupId>com.ubiqsecurity</groupId>
  <artifactId>ubiqsecurity</artifactId>
  <version>X.Y.Z</version>
</dependency>
```


### Others
You'll need to manually install the following JARs:

-  The Ubiq Security JAR from appropriate version in <https://repo1.maven.org/maven2/com/ubiqsecurity/ubiqsecurity/> 

#### Building from source:

Use following command to use [gradlew] to build the JAR file
```sh
#Linux / Mac
./gradlew assemble build
```
```dos
# windows
.\gradlew assemble build
```
## Requirements

-   OpenJDK 11 or later 
-   This library has dependancies on ubiq-fpe-java library available for download in the Ubiq GitHub/GitLab repository.


## Usage

The library needs to be configured with your account credentials which is
available in your [Ubiq Dashboard][dashboard] [credentials][credentials].
The credentials can be hardcoded into your application, specified with environment variables,
loaded from an explicit file, or loaded from a file in your 
home directory [~/.ubiq/credentials].



### Referencing the Ubiq Security library
Make sure your source files import these public types from the ```ubiqsecurity``` library:

```java
import com.ubiqsecurity.UbiqCredentials;
import com.ubiqsecurity.UbiqDecrypt;
import com.ubiqsecurity.UbiqEncrypt;
import com.ubiqsecurity.UbiqFactory;
```

### Read credentials from a specific file and use a specific profile 
```java
UbiqCredentials credentials = UbiqFactory.readCredentialsFromFile("some-credential-file", "some-profile");
```

### Read credentials from ~/.ubiq/credentials and use the default profile
```java
UbiqCredentials credentials = UbiqFactory.readCredentialsFromFile("", "default");
```

### Use the following environment variables to set the credential values
UBIQ_ACCESS_KEY_ID  
UBIQ_SECRET_SIGNING_KEY  
UBIQ_SECRET_CRYPTO_ACCESS_KEY  
```java
UbiqCredentials credentials = UbiqFactory.createCredentials(null, null, null, null);
```

### Explicitly set the credentials
```java
UbiqCredentials credentials = UbiqFactory.createCredentials("<yourAccessKey>", "<yourSigningKey>", "<yourCryptoKey>", null);
```

### Runtime exceptions

Unsuccessful requests raise exceptions. The exception object will contain the error details. 

### Encrypt a simple block of data

Pass credentials and plaintext bytes into the encryption function.  The encrypted data
bytes will be returned.

```java
import ubiqsecurity.UbiqCredentials;
import ubiqsecurity.UbiqEncrypt;

UbiqCredentials credentials = ...;
byte[] plainBytes = ...;
byte[] encryptedBytes = UbiqEncrypt.encrypt(credentials, plainBytes);
```

### Decrypt a simple block of data

Pass credentials and encrypted data into the decryption function.  The plaintext data
bytes will be returned.

```java
import ubiqsecurity.UbiqCredentials;
import ubiqsecurity.UbiqDecrypt;

UbiqCredentials credentials = ...;
byte[] encryptedBytes = ...;
byte[] plainBytes = UbiqDecrypt.decrypt(credentials, encryptedBytes);
```

### Encrypt a large data element where data is loaded in chunks

- Create an encryption object using the credentials.
- Call the encryption instance ```begin()``` method.
- Call the encryption instance ```update()``` method repeatedly until all the data is processed.
- Call the encryption instance ```end()``` method.

 Here's the example code from the reference source:

 ```java
static void piecewiseEncryption(String inFile, String outFile, UbiqCredentials ubiqCredentials)
        throws IOException, IllegalStateException, InvalidCipherTextException {
    try (FileInputStream plainStream = new FileInputStream(inFile)) {
        try (FileOutputStream cipherStream = new FileOutputStream(outFile)) {
            try (UbiqEncrypt ubiqEncrypt = new UbiqEncrypt(ubiqCredentials, 1)) {
                // start the encryption
                byte[] cipherBytes = ubiqEncrypt.begin();
                cipherStream.write(cipherBytes);

                // process 128KB at a time
                var plainBytes = new byte[0x20000];

                // loop until the end of the input file is reached
                int bytesRead = 0;
                while ((bytesRead = plainStream.read(plainBytes, 0, plainBytes.length)) > 0) {
                    cipherBytes = ubiqEncrypt.update(plainBytes, 0, bytesRead);
                    cipherStream.write(cipherBytes);
                }

                // finish the encryption
                cipherBytes = ubiqEncrypt.end();
                cipherStream.write(cipherBytes);
            }
        }
    }
}
```

### Decrypt a large data element where data is loaded in chunks

- Create a decryption object using the credentials.
- Call the decryption instance ```begin()``` method.
- Call the decryption instance ```update()``` method repeatedly until all data is processed.
- Call the decryption instance ```end()``` method

Here's the example code from the reference source:

 ```java
static void piecewiseDecryption(String inFile, String outFile, UbiqCredentials ubiqCredentials)
        throws FileNotFoundException, IOException, IllegalStateException, InvalidCipherTextException {
    try (FileInputStream cipherStream = new FileInputStream(inFile)) {
        try (FileOutputStream plainStream = new FileOutputStream(outFile)) {
            try (UbiqDecrypt ubiqDecrypt = new UbiqDecrypt(ubiqCredentials)) {
                // start the decryption
                byte[] plainBytes = ubiqDecrypt.begin();
                plainStream.write(plainBytes);

                // process 128KB at a time
                var cipherBytes = new byte[0x20000];

                // loop until the end of the input file is reached
                int bytesRead = 0;
                while ((bytesRead = cipherStream.read(cipherBytes, 0, cipherBytes.length)) > 0) {
                    plainBytes = ubiqDecrypt.update(cipherBytes, 0, bytesRead);
                    plainStream.write(plainBytes);
                }

                // finish the decryption
                plainBytes = ubiqDecrypt.end();
                plainStream.write(plainBytes);
            }
        }
    }
}
```




## Introducing FPE/eFPE

This library incorporates format preserving encryption (FPE) and embedded format preserving encryption (eFPE).

## Requirements

-   Please follow the same requirements as described above for the non-FPE functionality. 
-   FPE/eFPE requires an additional library called ubiq-fpe-java available for download in the Ubiq GitHub/GitLab repository.

## Usage

You will need to obtain account credentials in the same way as described above for conventional encryption/decryption. When
you do this in your [Ubiq Dashboard][dashboard] [credentials][credentials], you'll need to enable the FPE option. If you do not
see the FPE option, you may need to upgrade your plan as this is an optional capability available on upgraded accounts.
The credentials can be hardcoded into your application, specified with environment variables,
loaded from an explicit file, or loaded from a file in your 
home directory [~/.ubiq/credentials].


### Referencing the Ubiq Security library
Make sure your source files import these public types from the ```ubiqsecurity``` library:

```java
import com.ubiqsecurity.UbiqCredentials;
import com.ubiqsecurity.UbiqFPEEncryptDecrypt;
import com.ubiqsecurity.UbiqFactory;
```

### Reading and setting credentials

The FPE/eFPE functions work with the credentials file and/or environmental variables in the same way as described 
earlier in this document. You'll only need to make sure that the API keys you pull from the Ubiq dashboard are enabled for
FPE/eFPE capability. 


### Encrypt a social security text field

Lets assume you have a field containing a social security number "123-45-6789". You are able to encrypt the contents of that field
by adding these lines to your program:

```java
import ubiqsecurity.UbiqCredentials;
import ubiqsecurity.UbiqFPEEncryptDecrypt;
import com.ubiqsecurity.UbiqFactory;


ubiqCredentials = UbiqFactory.readCredentialsFromFile("path/to/file", "default");
String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "ALPHANUM_SSN", "123-45-6789", null); 
```


### Decrypt the encrypted social security cipher

To decrypt the cipher (e.g. "W$+-qF-oMMV") of a social security number, perform the following:

```java
import ubiqsecurity.UbiqCredentials;
import ubiqsecurity.UbiqFPEEncryptDecrypt;
import com.ubiqsecurity.UbiqFactory;


ubiqCredentials = UbiqFactory.readCredentialsFromFile("path/to/file", "default");
String plaintext = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "ALPHANUM_SSN", "W$+-qF-oMMV", null); 
```


### Other FFS models to explore

Depending on your installation, there are a wide variety of FFS models that are available. Each FFS model
imposes its own set of rules revolving around how the data is formatted and what characters are legal for the
given format. For example, you would not expect to see alpha characters in a social security number and the model
will identify that as a formatting error. A few models to consider are:

-   ALPHANUM_SSN 
-   BIRTH_DATE 
-   GENERIC_STRING 
-   SO_ALPHANUM_PIN

Additional information on how to use these FFS models in your own applications is available by contacting
Ubiq. You may also view some use-cases implemented in the unit test source file "UbiqFPEEncryptTest.java".



[dashboard]:https://dashboard.ubiqsecurity.com/
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
[gradlew]:https://docs.gradle.org/current/userguide/gradle_wrapper.html