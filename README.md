# Ubiq Security Java Library

The Ubiq Security Java library provides convenient interaction with the Ubiq Security Platform API from applications written in the Java language.  It includes a pre-defined set of classes that will provide simple interfaces to encrypt and decrypt data.

## Documentation

See the [Java API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

### Requirements
Java 8 or later

#### Gradle Users

Add this dependency to your project's build file:

```groovy
implementation group: 'com.ubiqsecurity', name: 'ubiqsecurity', version: 'latest.release'
```

#### Maven users
Add this dependency to your project's POM:
where X.Y.Z represents the appropriate version number.

```xml
<dependency>
  <groupId>com.ubiqsecurity</groupId>
  <artifactId>ubiqsecurity</artifactId>
  <version>X.Y.Z</version>
</dependency>
```


#### Others
The following is a list of the JAR files required to compile, test, or deploy the ubiqsecurity library

- [ubiqsecurity-2.2.2.jar](https://repo1.maven.org/maven2/com/ubiqsecurity/ubiqsecurity/2.2.2/ubiqsecurity-2.2.2.jar)
- [bcprov-jdk18on-1.76.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.76/bcprov-jdk18on-1.76.jar)
- [bcutil-jdk18on-1.76.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcutil-jdk18on/1.76/bcutil-jdk18on-1.76.jar)
- [bcpkix-jdk18on-1.76.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-jdk18on/1.76/bcpkix-jdk18on-1.76.jar)
- [gson-2.10.jar](https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10/gson-2.10.jar)
- [guava-18.0.jar](https://repo1.maven.org/maven2/com/google/guava/guava/18.0/guava-18.0.jar)
- [httpclient-4.5.14.jar](https://repo1.maven.org/maven2/org/apache/httpcomponents/httpclient/4.5.14/httpclient-4.5.14.jar)
- [httpcore-4.4.16.jar](https://repo1.maven.org/maven2/org/apache/httpcomponents/httpcore/4.4.16/httpcore-4.4.16.jar)
- [commons-codec-1.11.jar](https://repo1.maven.org/maven2/commons-codec/commons-codec/1.11/commons-codec-1.11.jar)
- [commons-logging-1.2.jar](https://repo1.maven.org/maven2/commons-logging/commons-logging/1.2/commons-logging-1.2.jar)
- [jcommander-1.78.jar](https://repo1.maven.org/maven2/com/beust/jcommander/1.78/jcommander-1.78.jar)
- [json-simple-1.1.1.jar](https://repo1.maven.org/maven2/com/googlecode/json-simple/json-simple/1.1.1/json-simple-1.1.1.jar)
- [junit-4.13.1.jar](https://repo1.maven.org/maven2/junit/junit/4.13.1/junit-4.13.1.jar)

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
### Requirements

-   OpenJDK 8 or later


## Usage

The library needs to be configured with your account credentials which is
available in your [Ubiq Dashboard][dashboard] [credentials][credentials].
The credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).  A configuration can also be supplied to control specific behavior of the library.  The configuration file can be loaded from an explicit file or read from the default location [~/.ubiq/configuration].  See [below](#configuration-file) for a sample configuration file and content description.  The credentials object needs to be initialized using the configuration object and the credentials.init method.  The credentials object only needs to be initialized one time, even if it is used to encrypt / decrypt many different object. 





### Referencing the Ubiq Security library
Make sure your source files import these public types from the ```ubiqsecurity``` library:

```java
import com.ubiqsecurity.UbiqCredentials;
import com.ubiqsecurity.UbiqConfiguration;
import com.ubiqsecurity.UbiqDecrypt;
import com.ubiqsecurity.UbiqEncrypt;
import com.ubiqsecurity.UbiqFactory;
```


### Read configuration from a specific file

```java
UbiqConfiguration cfg = UbiqFactory.readConfigurationFromFile(file.getAbsolutePath());
```


### Read credentials from a specific file and use a specific profile
```java
UbiqCredentials credentials = UbiqFactory.readCredentialsFromFile("some-credential-file", "some-profile");
```

### Read credentials from ~/.ubiq/credentials and use the default profile
```java
UbiqCredentials credentials = UbiqFactory.readCredentialsFromFile("", "default");
```

### Read configuration from ~/.ubiq/configuration if it exists or use default values
```java
UbiqConfiguration cfg = UbiqFactory.defaultConfiguration()

// Use the configuration to finish initalizing the credentials
credentials.init(configuration);

```

### Use the following environment variables to set the credential values
UBIQ_ACCESS_KEY_ID
UBIQ_SECRET_SIGNING_KEY
UBIQ_SECRET_CRYPTO_ACCESS_KEY
```java
UbiqCredentials credentials = UbiqFactory.createCredentials(null, null, null, null, null, null);
```

### Explicitly set the credentials
```java
UbiqCredentials credentials = UbiqFactory.createCredentials("<yourAccessKey>", "<yourSigningKey>", "<yourCryptoKey>", null, null, null);
```

### IDP integration
Ubiq currently supports both Okta and Entra IDP integration.  Instead of using the credentials provided when creating the API Key, the username (email) and password will be used to authenticate with the IDP and provide access to the Ubiq platform.

### Use the following environment variables to set the credential values
UBIQ_IDP_USERNAME  
UBIQ_IDP_PASSWORD  
```java
UbiqCredentials credentials = UbiqFactory.createCredentials(null, null, null, null, null, null);
```

### Explicitly set the credentials
```java
UbiqCredentials credentials = UbiqFactory.createCredentials(null, null, null, null, "<your_idp_username>", "<your_idp_password>");
```
### Runtime exceptions

Unsuccessful requests raise exceptions. The exception object will contain the error details.

### Unstructured encryption of a simple block of data

Pass credentials and plaintext bytes into the unstructured encryption function.  The encrypted data
bytes will be returned.

```java
import ubiqsecurity.UbiqCredentials;
import ubiqsecurity.UbiqEncrypt;

UbiqCredentials credentials = ...;
byte[] plainBytes = ...;
byte[] encryptedBytes = UbiqEncrypt.encrypt(credentials, plainBytes);
```

### Unstructured decryption of a simple block of data

Pass credentials and encrypted data into the unstructured decryption function.  The plaintext data
bytes will be returned.

```java
import ubiqsecurity.UbiqCredentials;
import ubiqsecurity.UbiqDecrypt;

UbiqCredentials credentials = ...;
byte[] encryptedBytes = ...;
byte[] plainBytes = UbiqDecrypt.decrypt(credentials, encryptedBytes);
```

### Unstructured encryption of a large data element where data is loaded in chunks

- Create an unstructured encryption object using the credentials.
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

### Encrypt several objects using the same data encryption key (fewer calls to the server)

In this example, the same data encryption key is used to encrypt several different plain text objects, object1 .. objectn.  In each case, a different initialization vector, IV, is automatically used but the ubiq platform is not called to obtain a new data encryption key, resulting in better throughput.  For data security reasons, you should limit n to be less than 2^32 (4,294,967,296) for each unique data encryption key.

1. Create an encryption object using the credentials.
2. Repeat following three steps as many times as appropriate
*  Call the encryption instance begin method
*  Call the encryption instance update method repeatedly until a single object's data is processed
*  Call the encryption instance end method
3. Call the encryption instance close method

```java
      UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("path/to/file", "default");

      ... 
      UbiqEncrypt ubiqEncrypt = new UbiqEncrypt(ubiqCredentials, 1);

      List<Byte> cipherBytes = new ArrayList<Byte>();
      // object1 is a full unencrypted object
      byte[] tmp = ubiqEncrypt.begin();
      cipherBytes.addAll(Bytes.asList(tmp))
      tmp = ubiqEncrypt.update(object1, 0, object1.length);
      cipherBytes.addAll(Bytes.asList(tmp))
      tmp = ubiqEncrypt.end();
      cipherBytes.addAll(Bytes.asList(tmp))
      // Do something with the encrypted data: cipherBytes

      // In this case, object2 is broken into two pieces, object2_part1 and object2_part2
      cipherBytes = new ArrayList<Byte>();
      tmp = ubiqEncrypt.begin();
      cipherBytes.addAll(Bytes.asList(tmp))
      tmp = ubiqEncrypt.update(object2_part1, 0, object2_part1.length);
      cipherBytes.addAll(Bytes.asList(tmp))
      tmp = ubiqEncrypt.update(object2_part2, 0, object2_part2.length);
      cipherBytes.addAll(Bytes.asList(tmp))
      tmp = ubiqEncrypt.end();
      cipherBytes.addAll(Bytes.asList(tmp))
      // Do something with the encrypted data: cipherBytes

      ...
      // In this case, objectb is broken into two pieces, object2_part1 and object2_part2
      cipherBytes = new ArrayList<Byte>();
      // objectn is a full unencrypted object
      tmp = ubiqEncrypt.begin();
      cipherBytes.addAll(Bytes.asList(tmp))
      tmp = ubiqEncrypt.update(objectn, 0, objectn.length);
      cipherBytes.addAll(Bytes.asList(tmp))
      tmp = ubiqEncrypt.end();
      cipherBytes.addAll(Bytes.asList(tmp))
      // Do something with the encrypted data: cipherBytes

      ubiqEncrypt.close()
}
```

### Unstructured decryption of a large data element where data is loaded in chunks

- Create a unstructured decryption object using the credentials.
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

## Ubiq Structured Encryption

## Requirements

-   Please follow the same requirements as described above for the unstructured encryption.

## Usage

You will need to obtain account credentials in the same way as described above for unstructured encryption/decryption. When
you do this in your [Ubiq Dashboard][dashboard] [credentials][credentials], you'll need to use a structured dataset.
The credentials can be set using environment variables, loaded from an explicitly
specified file, or read from the default location (~/.ubiq/credentials).


### Referencing the Ubiq Security library
Make sure your source files import these public types from the ```ubiqsecurity``` library:

```java
import com.ubiqsecurity.UbiqCredentials;
import com.ubiqsecurity.UbiqStructuredEncryptDecrypt;
import com.ubiqsecurity.UbiqFactory;
```

### Reading and setting credentials

The structured encryption functions work with the credentials file and/or environmental variables in the same way as described
earlier in this document. You'll only need to make sure that the API keys you pull from the Ubiq dashboard are associated with a structured dataset


### Encrypt a social security text field
Create an Encryption / Decryption object with the credentials and then allow repeatedly call encrypt
data using a structured dataset and the data.  The encrypted data will be returned after each call

```java
import ubiqsecurity.UbiqCredentials;
import ubiqsecurity.UbiqStructuredEncryptDecrypt;
import com.ubiqsecurity.UbiqFactory;

String datasetName = "SSN";
String plainText = "123-45-6789";

UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("path/to/file", "default");
// Create single object but use many times
try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
  // Can call encrypt / decrypt many times without creating new UbiqStructuredEncryptDecrypt object.
  String cipherText = ubiqEncryptDecrypt.encrypt(datasetName, plainText, null);
}
```

### Decrypt a social security text field
Create an Encryption / Decryption object with the credentials and then repeatedly decrypt
data using a structured dataset and the data.  The decrypted data will be returned after each call.


```java
import ubiqsecurity.UbiqCredentials;
import ubiqsecurity.UbiqStructuredEncryptDecrypt;
import com.ubiqsecurity.UbiqFactory;

String datasetName = "SSN";
String cipherText = "7\"c-`P-fGj?";

UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("path/to/file", "default");
// Create single object but use many times
try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
  // Can call encrypt / decrypt many times without creating new UbiqStructuredEncryptDecrypt object.
  String plainText = ubiqEncryptDecrypt.encrypt(datasetName, cipherText, null);
}
```
## Custom Metadata for Usage Reporting
There are cases where a developer would like to attach metadata to usage information reported by the application.  Both the structured and unstructured interfaces allow user_defined metadata to be sent with the usage information reported by the libraries.

The <b>addReportingUserDefinedMetadata</b> function accepts a string in JSON format that will be stored in the database with the usage records.  The string must be less than 1024 characters and be a valid JSON format.  The string must include both the <b>\{</b> and <b>\}</b> symbols.  The supplied value will be used until the object goes out of scope.  Due to asynchronous processing, changing the value may be immediately reflected in subsequent usage.  If immediate changes to the values are required, it would be safer to create a new encrypt / decrypt object and call the <b>addReportingUserDefinedMetadata</b> function with the new values.

Examples are shown below.
```
...
try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
   ubiqEncryptDecrypt.addReportingUserDefinedMetadata("{\"some_meaningful_flag\" : true }")
   ....
   // Structured Encrypt and Decrypt operations
}
```

```
...
try (UbiqEncrypt ubiqEncrypt = new UbiqEncrypt(ubiqCredentials, 1)) {
   ubiqEncrypt.addReportingUserDefinedMetadata("{\"some_key\" : \"some_value\" }")
   ....
   // Unstructured Encrypt operations
}

```
## Encrypt For Search
The same plaintext data will result in different cipher text when encrypted using different data keys.  The Encrypt For Search function will encrypt the same plain text for a given dataset using all previously used data keys.  This will provide a collection of cipher text values that can be used when searching for existing records where the data was encrypted and the specific version of the data key is not known in advance.

```java
String dataset_name = "SSN";
String plainText = "123-45-6789";
final byte[] tweak = null;

UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("path/to/file", "default");
UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials);
String[] ct_arr = ubiqEncryptDecrypt.encryptForSearch(dataset_name, plainText, tweak);
```

Additional information on how to use these datasets in your own applications is available by contacting
Ubiq. You may also view some use-cases implemented in the unit test [UbiqStructuredEncryptTest.java] and the sample application [UbiqSampleStructured.java] source code

### Configuration File

A sample configuration file is shown below.  The configuration is in JSON format.  

#### Event Reporting
The <b>event_reporting</b> section contains values to control how often the usage is reported.  

- <b>wake_interval</b> indicates the number of seconds to sleep before waking to determine if there has been enough activity to report usage
- <b>minimum_count</b> indicates the minimum number of usage records that must be queued up before sending the usage
- <b>flush_interval</b> indicates the sleep interval before all usage will be flushed to server.
- <b>trap_exceptions</b> indicates whether exceptions encountered while reporting usage will be trapped and ignored or if it will become an error that gets reported to the application
- <b>timestamp_granularity</b> indicates the how granular the timestamp will be when reporting events.  Valid values are
  - "NANOS"  
    // DEFAULT: values are reported down to the nanosecond resolution when possible
  - "MILLIS"  
  // values are reported to the millisecond
  - "SECONDS"  
  // values are reported to the second
  - "MINUTES"  
  // values are reported to minute
  - "HOURS"  
  // values are reported to hour
  - "HALF_DAYS"  
  // values are reported to half day
  - "DAYS"  
  // values are reported to the day

#### Key Caching
The <b>key_caching</b> section contains values to control how and when keys are cached.

- <b>ttl_seconds</b> indicates how many seconds a cache element should remain before it must be re-retrieved. (default: 1800)
- <b>structured</b> indicates whether keys will be cached when doing structured encryption and decryption. (default: true)
- <b>unstructured</b> indicates whether keys will be cached when doing unstructured decryption. (default: true)
- <b>encrypt</b> indicates if keys should be stored encrypted. If keys are encrypted, they will be harder to access via memory, but require them to be decrypted with each use. (default: false)

#### IDP specific parameters
- <b>provider</b> indicates the IDP provider, either <b>okta</b> or <b>entra</b>
- <b>ubiq_customer_id</b> The UUID for this customer.  Will be provided by Ubiq.
- <b>idp_token_endpoint_url</b> The endpoint needed to authenticate the user credentials, provided by Okta or Entra
- <b>idp_tenant_id</b> contains the tenant value provided by Okta or Entra
- <b>idp_client_secret</b> contains the client secret value provided by Okta or Entra

```json
{
  "event_reporting": {
    "wake_interval": 1,
    "minimum_count": 2,
    "flush_interval": 2,
    "trap_exceptions": false,
    "timestamp_granularity" : "NANOS"
  },
  "key_caching" : {
     "structured" : true,
     "unstructured" : true,
     "encrypted" : false,
     "ttl_seconds" : 1800
  },
   "idp": {
    "provider": "okta",
    "ubiq_customer_id": "f6f.....08c5",
    "idp_token_endpoint_url": " https://dev-<domain>.okta.com/oauth2/v1/token",
    "idp_tenant_id": "0o....d7",
    "idp_client_secret": "yro.....2Db"
  }
}
```
## Ubiq API Error Reference

Occasionally, you may encounter issues when interacting with the Ubiq API. 

| Status Code | Meaning | Solution |
|---|---|---|
| 400 | Bad Request | Check name of datasets and credentials are complete. |
| 401 | Authentication issue | Check you have the correct API keys, and it has access to the datasets you are using.  Check dataset name. |
| 426 | Upgrade Required | You are using an out of date version of the library, or are trying to use newer features not supported by the library you are using.  Update the library and try again.
| 429 | Rate Limited | You are performing operations too quickly. Either slow down, or contact support@ubiqsecurity.com to increase your limits. | 
| 500 | Internal Server Error | Something went wrong. Contact support if this persists.  | 
| 504 | Internal Error | Possible API key issue.  Check credentials or contact support.  | 

[dashboard]:https://dashboard.ubiqsecurity.com/
[credentials]:https://dev.ubiqsecurity.com/docs/api-keys
[gradlew]:https://docs.gradle.org/current/userguide/gradle_wrapper.html
[UbiqStructuredEncryptTest.java]:https://gitlab.com/ubiqsecurity/ubiq-java/-/blob/master/src/test/java/com/ubiqsecurity/UbiqStructuredEncryptTest.java
[UbiqSampleStructured.java]:https://gitlab.com/ubiqsecurity/ubiq-java/-/blob/master/example/src/main/java/UbiqSampleStructured.java
