# p2-create-sign-verify-rsa-keys
Using JCProv, a library provided by Gemalto, this program creates one RSA Key pair, performs a signature and verify the signature using the Luna HSMs.
This project is an extension of my other project "p1-creatersakeys" (https://github.com/SuperCrypto/p1-creatersakeys)

## Eclipse Project:
This project is being provided with the whole Eclipse Project folder.
In order to compile using Eclipse IDE, you need:
- Copy folder LIBRARIES to C:\ **OR** modify file .classpath in order to find the required libraries.
- On Eclipse, check if External Jars (commons-cli-1.3.1.jar, commons-codec-1.10.jar and jcprov.jar) are there (see file **eclipse1.png** for more information)

## Pre-requisites:
- To have Luna client installed
- Partition assigned to the client
- Check your slot list using:
```
vtl listslots
Number of slots: 1

The following slots were found:

Slot Description          Label                            Serial #         Status
==== ==================== ================================ ================ ============
   0 Net Token Slot       partition-01                     3423358          Present
```
On the above output, my target Slot = 0.
   
   

## Using:
- Go to Folder PprjRsaKeys\jar-git
- On the command prompt, run:
```
 java -jar CreateRsaKeys.jar <OPTIONS> 
```

## Help
Getting help:
```
java -jar Create-Sign-Verify-RSA.jar
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
SuperCrypto.jar
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
------------------------------------------------------------------------
-=- -=- -=- -=- -=- CREATE RSA KEYS -=- -=- -=- -=- -=-
usage: SuperCrypto.jar [-k <arg>] [-o <arg>] [-p <arg>] [-pr <arg>] [-pu <arg>] [-s <arg>] [-sa <arg>]
 -k,--keySize <arg>            Valid sizes: [512, 1024, 2048, 3072, 4096,
                               8192]
 -o,--operation <arg>          [createRsaKeys, signVerify]
 -p,--password <arg>           partition password
 -pr,--privateKeyLabel <arg>   Valid chars: [a-z, A-Z, 0-9, -, _, .]
 -pu,--publicKeyLabel <arg>    Valid chars: [a-z, A-Z, 0-9, -, _, .]
 -s,--slot <arg>               slot identifier
 -sa,--salt <arg>              yes / no

Example:
java -jar SuperCrypto.jar -s 0 -p Pwd-0123 -o createRsaKeys -pr LABEL-PRV -pu LABEL-PUB -k 2048 -sa yes

------------------------------------------------------------------------

-=- -=- -=- -=- -=- SIGN AND VERIFY -=- -=- -=- -=- -=-
usage: SuperCrypto.jar [-o <arg>] [-p <arg>] [-pr <arg>] [-pu <arg>] [-s <arg>]
 -o,--operation <arg>          [createRsaKeys, signVerify]
 -p,--password <arg>           partition password
 -pr,--privateKeyLabel <arg>   Valid chars: [a-z, A-Z, 0-9, -, _, .]
 -pu,--publicKeyLabel <arg>    Valid chars: [a-z, A-Z, 0-9, -, _, .]
 -s,--slot <arg>               slot identifier
 -t,--text <arg>               Any String delimited with double-quotes
 
Example:
java -jar SuperCrypto.jar -s 0 -p Pwd-0123 -o signVerify -pr LABEL-PRV -pu LABEL-PUB

------------------------------------------------------------------------
```

## Step 1 - Create the RSA Key Pair
```
 java -jar CreateRsaKeys.jar -s 0 -p Password#123 -k 2048 -sa yes -pr MY-PRIVATE -pu MY-PUBLIC 

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
CreateRsaKeys
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Session Opened
Login finished
Private key with the given label already exists?
>No, we are good to proceed
Starting Generate Key Pair process
Salt is ON
Calling GenerateKeyPair method
>Keys generated sucessfully
Private key is in the HSM? Let me check...
>Yes, it is!
Finished key pair generation.
Logout done
Session closed
Library finalizjava ed
```

As you can see, the program points step-by-step what it is doing, so you can easily see how the interaction is happening.

## Step 2 - Sign and Verify using the key pair created in Step 1
```
java -jar Create-Sign-Verify-RSA.jar -s 0 -p Password#123 -o signVerify -pr LABEL-PRV -pu LABEL-PUB
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
SuperCrypto.jar
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Session Opened
Login finished
Private key with the given label already exists?
>Private Key with the label LABEL-PRV exists! We are good to proceed.
Public key with the given label already exists?
>Public Key with the label LABEL-PUB exists! We are good to proceed.
PlainText = MY TEXT
Signature initialized using RSA_X_509
Calculated Hash: [B@36baf30c
Signature: com.safenetinc.jcprov.constants.CK_RV@7
Signature Verification: OK
Logout done
Session closed
Library finalized
```
As for Step 1, pass the required parameters for the previously created Private and Public RSA keys and the text to be signed and verified. 


## Getting Professional Support
Email to: supercrypto.contact@gmail.com
