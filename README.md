# NAC-ABE: Named-based Access Control with Attribute-based Encryption

## 1. Overview

Named Data Networking Attribute-based Encryption Support Library: **NAC-ABE**

[![Build Status](https://travis-ci.org/Zhiyi-Zhang/NAC-ABE.svg?branch=master)](https://travis-ci.org/Zhiyi-Zhang/NAC-ABE)

## 2. Quick Start

### 2.1 Dependency

#### 2.1.1 ndn-cxx

NAC-ABE is implemented over the Named Data Networking.
To install the NAC-ABE library, you need to first install [ndn-cxx library](https://github.com/named-data/ndn-cxx).

#### 2.1.2 openabe

NAC-ABE is using cryptography support provided by library openabe. 
To install openable, you can visit the [website](https://github.com/zeutro/openabe).

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

## 3 Citation

The publication of this work is [NAC: Automating Access Control via Named Data](https://arxiv.org/abs/1902.09714) on IEEE MILCOM 2018.

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

## 4 Contact

If you have any problems or want to do bug report. Please contact us.

* Yufeng Zhang (yufeng@ucla.edu)
* Zhiyi Zhang (zhiyi@cs.ucla.edu).
* Yukai Tu (ytu@cs.ucla.edu)
