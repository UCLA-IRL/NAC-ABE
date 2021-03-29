# NAC-ABE: Named-based Access Control with Attribute-based Encryption

## 1. Overview

Named Data Networking Attribute-based Encryption Support Library: **NAC-ABE**

[![Build Status](https://travis-ci.org/Zhiyi-Zhang/NAC-ABE.svg?branch=master)](https://travis-ci.org/Zhiyi-Zhang/NAC-ABE)

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

To work with the version 0.0.1, please checkout to NDN-CXX 0.7.0 and install.

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
* **Data owner**. The party who decides how encryptors should encrypt their data. 
* **Encryptor**. The party who get decryption keys from the attribute authority and consume encrypted data.
* **Decryptor**. The party who follows data owner's decision and produce encrypted data.

These four parties are implemented in four classes in the library: `AttributeAuthority`, `DataOwner`, `producer`, and `consumer`.

> For now, only Ciphertext Policy Attribute-based Encryption (CP-ABE) is supported. 
> A future work is to support KP-ABE as well so that the application can decide the favor based on its requirements.

### 3.1 Attribute Authority


## 4 Contact

If you have any problems or want to do bug report. Please submit a GitHub issue.