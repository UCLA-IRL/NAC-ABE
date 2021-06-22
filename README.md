# NAC-ABE: Named-based Access Control with Attribute-based Encryption

[![Build Status](https://travis-ci.org/Zhiyi-Zhang/NAC-ABE.svg?branch=master)](https://travis-ci.org/Zhiyi-Zhang/NAC-ABE)

## 1. Overview

Named Data Networking Attribute-based Encryption Support Library: **NAC-ABE**

The publication of this work is [NAC: Automating Access Control via Named Data](https://arxiv.org/abs/1902.09714) on IEEE MILCOM 2018.
To cite the work, you can use the following Bibtex entry.

```latex
@inproceedings{zhang2018nac,
  title={NAC: Automating access control via Named Data},
  author={Zhang, Zhiyi and Yu, Yingdi and Ramani, Sanjeev Kaushik and Afanasyev, Alex and Zhang, Lixia},
  booktitle={MILCOM 2018-2018 IEEE Military Communications Conference (MILCOM)},
  pages={626--633},
  year={2018},
  organization={IEEE}
}
```

## 2. Quick Start

### 2.1 Dependency

#### 2.1.1 ndn-cxx

NAC-ABE is implemented over the Named Data Networking.
To install the NAC-ABE library, you need to first install [ndn-cxx library](https://github.com/named-data/ndn-cxx).

To work with the version 0.1.0, please checkout to NDN-CXX 0.7.0 and install.

To work with the master version, please checkout to NDN-CXX 0.7.1 and install.


#### 2.1.2 openabe

NAC-ABE is using cryptography support provided by library openabe. 
To install openable, you can visit the [website](https://github.com/zeutro/openabe).

> (As noticed in Mar 28, 2020) 
> When installing the OpenABE, there could be some issues installing gTest (on Ubuntu) or Bison 3.3 (on MacOS). 
> While waiting for the OpenABE maintainer to fix them, as a quick solution, you can fix these issues manually.

### 2.2 Install NAC-ABE

Really simple to make it using waf.

#### 2.2.1 Download

```bash
git clone https://github.com/UCLA-IRL/NAC-ABE.git
```

#### 2.2.2 Config

```bash
# in the root directory of NAC-ABE
./waf configure
```

or if you want to enable tests.

```bash
./waf configure --with-tests
```

#### 2.2.3 Compile

```bash
# in the root directory of NAC-ABE
./waf
```

#### 2.2.4 Install (sudo might be needed)

```bash
# in the root directory of NAC-ABE
./waf install
```

### 2.3 Run Tests

To run tests, you must have `--with-tests` when you config the project.

```bash
# in the root directory of NAC-ABE
#run all the tests (including integrate test)
./build/unit-tests
```

## 3 Documentation

The library mainly provide supports for four roles in an NDN based ABE scenario.

* **Attribute Authority**. The party who owns the system master key. It publishes the public parameters to the system and generate decryption keys for decryptors.
* **Data owner**. The party who decides how encryptors should cpEncrypt their data. 
* **Encryptor**. The party who get decryption keys from the attribute authority and consume encrypted data.
* **Decryptor**. The party who follows data owner's decision and produce encrypted data.

These four parties are implemented in four classes in the library: `AttributeAuthority`, `DataOwner`, `producer`, and `consumer`.

> For now, only Ciphertext Policy Attribute-based Encryption (CP-ABE) is supported. 
> A future work is to support KP-ABE as well so that the application can decide the favor based on its requirements.

From the perspective of the data flow:
* Content is encrypted by the content KEY (CK), which is symmetric AES key.
* CK is encrypted by the attribute policy (EKEY)
* CK can only be decrypted when the attributes (DKEY) can satisfy the EKEY
* Decryptor obtains an DKEY from attribute authorities
* Encryptor knows which EKEY to use from the data owner

### 3.1 Attribute Authority

#### Instantiate a new attribute authority

```c++
// obtain or create a certificate for attribute authority
AttributeAuthority aa = AttributeAuthority(aaCert, face, keychain);
```

#### Add policy

Add a new decryptor and its corresponding attribute list into authority:

```c++
// obtain the decryptor's certificate
std::list<std::string> attrList = {"ucla", "professor"};
aa.addNewPolicy(decryptorCertificate, attrList);
```

After starting an attribute authority and added policies for decryptors, 
the attribute authority will listen to the prefix `/<attribute authority prefix>/DKEY` to answer possible attribute request from decryptors.
When a request arrives, the attribute authority will first use a known decryptor cetificate to verify the request, then locates the attribtue lists of this decryptor.
After that, the attribute authority will create a new AES key to cpEncrypt the attributes, then use the decryptor's RSA public key from the certificate to cpEncrypt the AES key.
The encrypted attributes will be returned back to the decryptor.

### 3.2 Data Owner

#### Instantiate a new data owner

```c++
// obtain or create a certificate for data owner
DataOwner dataOwner = DataOwner(dataOwnerCert, face, keychain);
```

#### Command a data producer

Command a data producer to apply certain policy when producing certain Data packets.

```c++
dataOwner.commandProducerPolicy(Name("/producer"), Name("/healthdata"), "ucla and professor", successCallback, failCallback);
```

To command a data producer, the data owner will use its own private key to sign the command Interest.
The command Interest is of format: `/<producer prefix>/SET_POLICY/<data prefix block>/<policy string>`.

### 3.3 Encryptor (Data Producer)

#### Instantiate a new encryptor

```c++
Producer producer = Producer(face, keychain, producerCert, aaCert, dataOwnerCert);
```

After starting a encryptor, the encryptor will automatically fetch the public parameters from the attribute authority.

After starting a encryptor, the encryptor will listen to the prefix `/<producer prefix>/SET_POLICY` for the data owner to command the policy.
When a command Interest arrives, the encryptor will verify the command Interest with the data owner's certificate.

#### Produce a new data

```c++
std::shared_ptr<Data> contentData, ckData;
std::tie(contentData, ckData) = producer.produce(dataName, PLAIN_TEXT, sizeof(PLAIN_TEXT));
```

This function will automatically find the policy that is previously obtained from the command issued by the data owner.

The encryptor can also produce a new data using a new policy:

```c++
std::shared_ptr<Data> contentData, ckData;
std::tie(contentData, ckData) = producer.produce(dataName, "ucla and professor", sizeof(PLAIN_TEXT));
```

### 3.4 Decryptor (Data Consumer)

#### Instantiate a new decryptor

```c++
Consumer consumer = Consumer(face, keyChain, consumerCert, aaCert);
```

After starting a decryptor, the decryptor will automatically fetch the public parameters from the attribute authority.

#### Obtain the decryption key (DKEY), i.e., attributes

```c++
consumer.obtainAttributes();
```

This function will fetch the DKEY from the attribute authority.

#### Consume data

```c++
consumer.consume(dataName, successCallback, failCallback);
```

This function will fetch the content Data packet by the name, fetch the corresponding encrypted CK Data packet.
Then it uses its decryption key (DKEY) to cpDecrypt the CK, then use the CK to cpDecrypt the content Data packet.

## 4 Issue Report

If you have any problems or want to do bug report. 
Please submit a GitHub issue.
