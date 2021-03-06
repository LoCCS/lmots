# The Leighton-Micali One-Time Signature [LM-OTS]  

![version tag](https://img.shields.io/badge/lmots-v2.2.0-blue.svg) 
![build status](https://www.travis-ci.org/LoCCS/lmots.svg?branch=master)
[![license tag](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)  

Copyright (c) 2017-2018 LoCCS.  
Project to implement the Leighton-Micali one-time signature scheme according to [Hash-Based Signatures: draft-mcgrew-hash-sigs-08](https://datatracker.ietf.org/doc/draft-mcgrew-hash-sigs/).  

## Contents  
+ [Requirement](#requirement)  
+ [Installation](#installation)  
+ [Usage](#usage)  
+ [Contributing](#contrib)  
+ [Development Resources](#dev-res)  

## Requirement  
+ git  
+ go 1.9+  

are required to compile the library.

<a name="installation"></a>
## Installation  
### By `go get`  
```bash
$ go get -u github.com/LoCCS/lmots
```
### By [`dep`](https://github.com/golang/dep)    
1. download the source code into local disks  
2. invoke `dep` to build up dependencies  
```bash
$ dep ensure
```

<a name="usage"></a>
## Usage  
Please refer to `ExampleLMS()` in [example_test.go](example_test.go)    

<a name="contrib"></a>
## Contributing  
Kind advices and contributions are always welcomed, but to avoid chaos or destabilization in existing work, we have processes that bring people in gradually. In general the process is:  

+ Find a specific **bug** you'd like to fix or a specific **feature** you’d like to add (check out the issues list if to get some ideas)  
+ Fix the bug in your own clone and **ensure that it's working**   
+ Submit the change to the master branch via a **pull request**  

<a name="dev-res"></a>
## Development Resources  
+ [Github](https://github.com/LoCCS/lmots)  

