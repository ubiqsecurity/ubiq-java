## Ubiq Security Java Library

The Ubiq Security Java library provides convenient interaction with the Ubiq Security Platform API from applications written in the Java language.  It includes a pre-defined set of classes that will provide simple interfaces to encrypt and decrypt data.

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

Use following command to use gradlew to build the JAR file
```sh
./gradlew assemble build
```

## Requirements

-   OpenJDK 11 or later 

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

[dashboard]:https://dashboard.ubiqsecurity.com/
[credentials]:https://dev.ubiqsecurity.com/docs/how-to-create-api-keys
