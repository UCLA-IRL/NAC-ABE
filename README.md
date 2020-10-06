# NAC-ABE: Named-based Access Control with Attribute-based Encryption

## Overview

Named Data Networking Attribute-based Encryption Support Library: **NAC-ABE**

[![Build Status](https://travis-ci.org/yufengzh/NAC-ABE.svg?branch=master)](https://travis-ci.org/yufengzh/NAC-ABE)

## Quick Start

### Dependency

#### 1. ndn-cxx

NAC-ABE is implemented over the Named Data Networking.
Here is the link to [ndn-cxx library](https://github.com/named-data/ndn-cxx).
To install the NAC-ABE library, you need to first install ndn-cxx.

For Ubuntu users, 
#### 2. openabe

NAC-ABE is using cryptography support provided by library openabe. To install openable, you can visit the [website](https://github.com/zeutro/openabe).

For Ubuntu users, you can also build and install the openabe by using the following commands:

```bash
wget https://github.com/yufengzh/NAC-ABE/releases/download/v1.0/libopenabe-1.0.0-linux.tar.gz
tar xzvf libopenabe-1.0.0-linux.tar.gz
cd libopenabe-1.0.0-linux/
. ./env
make && sudo make install
sudo ldconfig
cd ..
```

### Install NAC-ABE

Really simple to make it using waf.

#### Config

```bash
# in the root directory of NAC-ABE
./waf configure
```

or if you want to enable tests.

```bash
./waf configure --with-tests
```

#### Compile

```bash
# in the root directory of NAC-ABE
./waf
```

#### Install (sudo might be needed)

```bash
# in the root directory of NAC-ABE
./waf install
```

### Run Tests

To run tests, you must have `--with-tests` when you config the project.

```bash
# in the root directory of NAC-ABE
#run all the tests (including integrate test)
./build/unit-tests
```

## Citation

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

## Contact

If you have any problems or want to do bug report. Please contact us.

* Yufeng Zhang (yufeng@ucla.edu)
* Zhiyi Zhang (zhiyi@cs.ucla.edu).
* Yukai Tu (ytu@cs.ucla.edu)