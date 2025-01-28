# Ubiq Security Sample Application using Java Library

Provided are two sample applications. One called "UbiqSample.java" demonstrates how to perform unstructured encryption and decryption on typical data that you might
encounter in your own applications. The other sample application called "UbiqSampleStructured.java" demonstrates how to perform structured encryption and decryption.


## Documentation for UbiqSample.java

See the [Java API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Install or build the library as described [here](/README.md#installation).

## Build From Source

Use gradlew to compile the sample application

```sh
#Linux / Mac
cd example
./gradlew clean assemble build --refresh-dependencies
```
```dos
# Windows
cd example
.\gradlew clean assemble build --refresh-dependencies
```

## Credentials file

Edit the credentials file with your account credentials created using the Ubiq dashboard

```sh
[default]
ACCESS_KEY_ID = ...
SECRET_SIGNING_KEY = ...
SECRET_CRYPTO_ACCESS_KEY = ...
```
## View Program Options

From within the example directory, use the ```java ``` command to execute the sample application for unstructured encryption

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -h
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -h
</pre>

<pre>
Usage: Ubiq Security Example [options]
  Options:
    --creds, -c
      Set the file name with the API credentials
    --decrypt, -d
      Decrypt the contents of the input file and write the results to output
      file
      Default: false
    --encrypt, -e
      Encrypt the contents of the input file and write the results to output
      file
      Default: false
    --help, -h
      Print app parameter summary
    --in, -i
      Set input file name
    --out, -o
      Set output file name
    --piecewise, -p
      Use the piecewise encryption / decryption interfaces
      Default: false
    --profile, -P
      Identify the profile within the credentials file
      Default: default
    --simple, -s
      Use the simple encryption / decryption interfaces
      Default: false
    --config, -g
      Set the file name for loading system configuration parameters
      Default: ~/.ubiq/configuration
    --version, -v
      Print the app version
      Default: false
</pre>


#### Demonstrate using the simple (-s / --simple) API interface to perform unstructured encryption on README.md file and write the encrypted data to readme.enc

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -s -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -s -c credentials
</pre>

#### Demonstrate using the simple (-s / --simple) API interface to perform unstructured decryption on readme.enc file and write the decrypted output to README.out

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -s -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -s -c credentials
</pre>

#### Demonstrate using the piecewise (-p / --piecewise) API interface to perform unstructured encryption on README.md file and write the encrypted data to readme.enc

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -p -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -p -c credentials
</pre>

#### Demonstrate using the piecewise (-p / --piecewise) API interface to perform unstructured decryption the readme.enc file and write the decrypted output to README.out

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -p -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -p -c credentials
</pre>




## Documentation for UbiqSampleStructured.java

See the [Java API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Install or build the library as described [here](/README.md#installation).

## Build From Source

Use gradlew to compile the sample application

```sh
#Linux / Mac
cd example
./gradlew clean assemble build --refresh-dependencies
```
```dos
# Windows
cd example
.\gradlew clean assemble build --refresh-dependencies
```

## Credentials file

Edit the credentials file with your account credentials created using the Ubiq dashboard.

```sh
[default]
ACCESS_KEY_ID = ...
SECRET_SIGNING_KEY = ...
SECRET_CRYPTO_ACCESS_KEY = ...
```
## View Program Options

From within the example directory, use the ```java ``` command to execute the structured encryption sample application

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSampleStructured  -h
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSampleStructured  -h
</pre>

<pre>
Usage: Ubiq Security Example [options]
  Options:
    --creds, -c
      Set the file name with the API credentials
    --decrypttext, -d
      Set the cipher text value to decrypt and will return the decrypted text.
    --encrypttext, -e
      Set the field text value to encrypt and will return the encrypted cipher
      text.
    --dataset, -n
      Set the dataset name, for example SSN.
    --help, -h
      Print app parameter summary
    --profile, -P
      Identify the profile within the credentials file
      Default: default
    --config, -g
      Set the file name for loading system configuration parameters
      Default: ~/.ubiq/configuration
    --version, -V
      Show program's version number and exit
</pre>



#### Demonstrate structured encryption of a social security number and returning a cipher text

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSampleStructured  -e '123-45-6789' -c credentials -n 'ALPHANUM_SSN' -s
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSampleStructured  -e '123-45-6789' -c credentials -n 'ALPHANUM_SSN' -s
</pre>

#### Demonstrate structured decryption of a social security number and returning the plain text

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSampleStructured  -d 'W$+-qF-oMMV' -c credentials -n 'ALPHANUM_SSN' -s
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSampleStructured  -d 'W$+-qF-oMMV' -c credentials -n 'ALPHANUM_SSN' -s
</pre>
