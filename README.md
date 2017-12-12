# The Leighton-Micali One-Time Signature  

## Interfaces  

interfaces | input | output
----------:|:-----:|:-------
key generation  | indication of parameters  | (sk,pk) 
signing         | msg, sk                   | sig, sk'  
verification    | pk, msg, sigma            | true/false

## Security String  

fields  | byte range  | meaning 
:------:|:-----------:|:--------:
I       | 0-15        | id for LMS sk/pk
r/q     | 16-19       | r is the index of particular node in the hash tree, q is index of leaf,
D       | 20-21       | domain separation parameter, determines either r or q to use
j       | 22          | idx of component in sk, present if D in [0,264]
C       | 22-(21+n)   | n-byte randomizer, present if D=D_MESG




## References  
+ [Hash-Based Signatures: draft-mcgrew-hash-sigs-08](https://datatracker.ietf.org/doc/draft-mcgrew-hash-sigs/)  
