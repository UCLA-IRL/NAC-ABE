# Phase1 Design Notes

**Author**: Zhiyi

**Date**:Dec 22, 2020

**Version**: 1

## 1. Example Scenario

Let's assume there are three institutes A, B, and C.

* A shall access all the streams
* B shall only access semantic-location stream (regular expression needed)
* C shall be able to access all the streams except gps-coordinates streams

Complete stream names are as follows:

*	`battery--org.md2k.phonesensor—phone`
* `location--org.md2k.phonesensor—phone: only GPS`
* `org.md2k.data_analysis.gps_episodes_and_semantic_location`
* `accelerometer--org.md2k.phonesensor--phone`
* `gyroscope--org.md2k.phonesensor—phone`

Policy for A,B,C in details:

Policy for institute A:

```policy
POLICY-ID: 1
STUDY-NAME: test-study
DATA-OWNER-ID: 123
SHARE-WITH: [A]
DATA-STREAM-NAME: *

DATA-WINDOW:

  ALLOW:
    StreamName: *
    ColumnName: *
    Value: *
```

Policy for institute B:

```policy
POLICY-ID: 2
STUDY-NAME: test-study
DATA-OWNER-ID: 123
SHARE-WITH: [B]
DATA-STREAM-NAME: org.md2k.data_analysis.gps_episodes_and_semantic_location

DATA-WINDOW:
  DENY:
    StreamName: *
    ColumnName: *
    Value: *
  ALLOW:
    StreamName:org.md2k.data_analysis.gps_episodes_semantic_location
    ColumnName: *
    Value: *
```

Policy for institute C:
```policy
POLICY-ID: 3
STUDY-NAME: test-study
DATA-OWNER-ID: 123
SHARE-WITH: [C]
DATA-STREAM-NAME: org.md2k.*

DATA-WINDOW:
  DENY:
    StreamName: location--org*
    ColumnName: *
    Value: *
  ALLOW:
    StreamName: *
    ColumnName: *
    Value: *
```


## 2. Design

### 2.1. Attribute and Policy

First, we can directly use stream name as attribute.
Therefore, we have attributes:

*	`battery--org.md2k.phonesensor—phone`
* `location--org.md2k.phonesensor—phone`
* `org.md2k.data_analysis.gps_episodes_and_semantic_location`
* `accelerometer--org.md2k.phonesensor--phone`
* `gyroscope--org.md2k.phonesensor—phone`

Depending on the policy of A, B, and C, naturally, we have the following policies:

* A: All of above attributes connected by `or`
* B: `org.md2k.data_analysis.gps_episodes_and_semantic_location`
* C: All of above attributes connected by `or` except `location--org.md2k.phonesensor—phone`

### 2.2. Parsing Policy

A parser of mguard policies is needed, in which we have:

**Input**: a mguard policy

**Output**: a string representing the NAC-ABE policy for the consumer

Design of the parser:

1. Check `deny` field and add corresponding ones into the blacklist. If it is a `*`, ignore it.
2. Check `allow` field and add corresponding ones into the whitelist.
3. Remove the `deny` attributes from the `allow` attributes.

Using the following policy as an example:
```policy
POLICY-ID: 3
STUDY-NAME: test-study
DATA-OWNER-ID: 123
SHARE-WITH: [C]
DATA-STREAM-NAME: org.md2k.*

DATA-WINDOW:
  DENY:
    StreamName: location--org*
    ColumnName: *
    Value: *
  ALLOW:
    StreamName: *
    ColumnName: *
    Value: *
```

1. Check `deny` field and remove corresponding ones

   * Here the `deny` field is `StreamName: location--org*`, so the parser will translate this regular expression into a list of attributes with prefix `location--org`.

2. Check `allow` field and add corresponding ones

   * Here the `allow` field is `*`, which matches all the attributes.

3. Remove the `deny` attributes from the `allow` attributes.

   * Will remove attributes with prefix `location--org` from the result attributes from Step 2.
   * Then connects all the attributes with `or`

### 2.3. Future Consideration

#### 2.3.1 New attributes after the setup of the system

* How to generate new attributes?

  Potential solution: Pre-allocate placeholder attributes and do mapping later

* How to update the keys owned by consumers?

  Solution: Need to renew corresponding consumers' keys.