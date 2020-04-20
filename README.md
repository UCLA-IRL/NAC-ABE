# NAC-ABE: NDN-Attribute-Based-Access-Control

## Overview

Named Data Networking Attribute-based Encryption Support Library: NAC-ABE

## Quick Start

### Dependency

#### 1. ndn-cxx

NAC-ABE is implemented over the Named Data Networking.
Here is the link to [ndn-cxx library](https://github.com/named-data/ndn-cxx).
To install the NAC-ABE library, you need to first install ndn-cxx.

#### 2. pbc

NAC-ABE is using paring-based cryptography support provided by library PBC. To install PBC, you can visit the [website](https://crypto.stanford.edu/pbc/).

Or a simple way:

```bash
brew search pbc
brew install pbc
```

#### 3. libbswabe

NAC-ABE is using attribute-encryption support provided by library [libbswabe](http://hms.isi.jhu.edu/acsc/cpabe/). You should download the libbwable library first and then install the library.

```bash
// after you have unzip the library
// in the root directory of libbswabe
./configure
make
make install
```

### Install NAC-ABE

Really simple to make it using waf.

#### Auto dependency check

```bash
// in the root directory of NAC-ABE
./waf configure
```

#### Compile

```bash
// in the root directory of NAC-ABE
./waf
```

#### Install

```bash
// in the root directory of NAC-ABE
./waf install
```

### Run Tests

```bash
// in the root directory of NAC-ABE
./waf configure --with-tests

// run all the tests (including integrate test)
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

* Zhiyi Zhang (zhiyi@cs.ucla.edu).
* Yukai Tu (ytu@cs.ucla.edu)