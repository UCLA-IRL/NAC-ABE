NDN-Attribute-Based-Access-Control
==================================


Overview
--------

There are two main parts in this project:

* Named Data Networking Attribute-based Encryption Support Library: ndn-abac
* Virtual Organization System Implementation


Quick Start
-----------

### Dependency ###

#### 1. ndn-cxx ####

ndn-abac is implemented over the Named Data Networking.
Here is the link to [ndn-cxx library](https://github.com/named-data/ndn-cxx).
To install the ndn-abac library, you need to first install ndn-cxx.

#### 2. pbc ####

ndn-abac is using paring-based cryptography support provided by library PBC. To install PBC, you can visit the [website](https://crypto.stanford.edu/pbc/).

Or a simple way:

```
// bash
brew search pbc
brew install pbc
```

#### 3. libbswabe ###

ndn-abac is using attribute-encryption support provided by library [libbswabe](http://hms.isi.jhu.edu/acsc/cpabe/). You should download the libbwable library first and then install the library.

```
// bash
// after you have unzip the library
// in the root directory of libbswabe
./configure
make
make install
```

### Install ndn-abac ###

Really simple to make it using waf.

#### Auto dependency check ####

```
// bash
// in the root directory of ndn-abac
./waf configure
```

#### Compile ndn-abac ####
```
// bash
// in the root directory of ndn-abac
./waf
```

#### Install ndn-abac ####
```
// bash
// in the root directory of ndn-abac
./waf install
```

Contact
-------

If you have any problems or want to do bug report. Please contact: 

* Zhiyi Zhang (zhiyi@cs.ucla.edu).
* Yukai Tu (ytu@cs.ucla.edu)
