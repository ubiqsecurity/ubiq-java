# Ubiq Security Sample Application using Java Library

This sample application will demonstrate how to encrypt and decrypt data using the different APIs.


### Documentation

See the [Java API docs](https://dev.ubiqsecurity.com/docs/api).

## Installation

Install or build the library as described [here](/README.md#installation).

## Build From Source

Use gradlew to compile the sample application

```sh
#Linux / Mac
cd example
./gradlew assemble build
```
```dos
# Windows
cd example
.\gradlew assemble build
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

From within the example directory, use the ```java ``` command to execute the sample application

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
  * --in, -i
      Set input file name
  * --out, -o
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
    --version, -v
      Print the app version
      Default: false
</pre>


#### Demonstrate using the simple (-s / --simple) API interface to encrypt this README.md file and write the encrypted data to readme.enc

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -s -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -s -c credentials
</pre>

#### Demonstrate using the simple (-s / --simple) API interface to decrypt the readme.enc file and write the decrypted output to README.out

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -s -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -s -c credentials
</pre>

#### Demonstrate using the piecewise (-p / --piecewise) API interface to encrypt this README.md file and write the encrypted data to readme.enc

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -p -c credentials
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i README.md -o readme.enc -e -p -c credentials
</pre>

#### Demonstrate using the piecewise (-p / --piecewise) API interface to decrypt the readme.enc file and write the decrypted output to README.out

<pre>
# Linux / Mac
java -cp "./build/libs/ubiq-sample.jar:./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -p -c credentials 
</pre>
<pre>
# Windows
java -cp "./build/libs/ubiq-sample.jar;./build/deps/lib/*"  UbiqSample -i readme.enc -o README.out -d -p -c credentials 
</pre>


