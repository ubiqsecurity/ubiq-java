# Changelog

## 2.2.7 - 2025-06-05
* Added support for HTTP and HTTPS proxies

## 2.2.6 - 2025-06-02
* Fix issue with multi-threading for structured datasets

## 2.2.5 - 2025-02-27
* Minor change in the configuration file for IDP support

## 2.2.4 - 2025-01-22
* Added support for IDP integration using Okta and Entra

## 2.2.3 - 2024-10-16
* Improved support for Apigee and added unit tests for methods specific to Apigee

## 2.2.2 - 2024-09-16
* Key caching improvement for unstructured decryption
* Key caching options got structured encryption / decryption
* Deprecated simple interfaces for structured encryption
* Incorporated structured encryption submodule directly into this package
* Updated exception handling and updated README documentation
* Updated README code samples

## 2.2.1 - 2024-09-05
* Added support for key caching TTL

## 2.2.0 - 2024-04-24
* Support partial encryption rules

## 2.1.3 - 2023-12-13
* Updated dependency to include bcprov-jdk18on instead of bcprov-ext-jdk18on
* Update README.md with updated list of dependencies

## 2.1.2 - 2023-10-16
* Added support for different granular levels of reporting usage based on time
* Changed default configuration parameters to reduce rate of DB writes for billing records
* Changed version numbering mechanism to support unit-tests and Apigee
* Upgrade bouncy castle version to 1.76 jdk18on
* Updated README.md with list of dependencies

## 2.1.1 - 2023-09-26
* Added support for user defined metadata in the billing records

## 2.1.0 - 2023-09-05
* Port to Java 1.8

## 2.0.2 - 2023-06-20
* Performance improvements for EncryptForSearch

## 2.0.1 - 2023-05-17
* Updated to use standard data sets for unit tests

## 2.0.0 - 2023-04-19
* Updated usage configuration defaults.
* Updated bouncycastle version
* Updated library version

## 0.2.11 - 2023-03-22
* Added support for measuring metrics and performance

## 0.2.10 - 2023-01-09
* Performance improvements and support arbitrary radix / charactersets 
* Resolve https://nvd.nist.gov/vuln/detail/CVE-2022-25647 by updating to version 2.10

## 0.2.9 - 2022-05-03
* Added simple interfaces for fpe encryption

## 0.2.8 - 2022-04-13
* Fixed a Field Format Specification caching issue and added appropriate unittests

## 0.2.7 - 2022-02-16
* Improved error handling with billing messages during library shutdown

## 0.2.6 - 2021-10-12
* Improved error handling / reporting in FPE/eFPE processing

## 0.2.5 - 2021-09-29
* Added FPE/eFPE capability

## 0.2.4 - 2021-01-26
* Update to bouncy castle 1.68

## 0.2.3 - 2020-10-28
* Change to MIT license

## 0.2.2 - 2020-10-14
* Added explicit commands for Windows Operating System
* Added java version into API call

## 0.2.1 - 2020-09-29
* Initial Version
