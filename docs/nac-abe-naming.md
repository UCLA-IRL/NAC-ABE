# Naming

## Public Params
Requested Prefix:
```
/<aa-prefix>*/PUBPARAMS/
```
Replied param format:
```
/<aa-prefix>*/PUBPARAMS/<abe-type>/metadata=32/<timestamp>
/<aa-prefix>*/PUBPARAMS/<abe-type>/<timestamp>/<segment>
```
In the public param metadata packet, the metadata field contains the type of encryption scheme. 

## Decryption Keys
Requested Interest:
```
/<AA-prefix>/DKEY/<identity-name-block>/<signature>
```

Replied Data: 
```
/<AA-prefix>/DKEY/<identity-name-block>/metadata=32/<timestamp> (follows RDR)
/<AA-prefix>/DKEY/<identity-name-block>/<timestamp>/<segment>
```
In the metadata packet, the version of corresponding public param is provided. 

## Policy Set
```
/<producer prefix>/SET_POLICY/<data prefix block>/<attribute or policy block>
```

## Content Key
```
/<producer prefix>/CK/<random number identifier>
```