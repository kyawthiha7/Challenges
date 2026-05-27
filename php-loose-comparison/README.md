# PHP Loose Comparison — CTF Challenge

**Category:** Web  
**Difficulty:** Easy  

## Description

A simple admin panel protects a flag behind a password check. The developer used PHP's `==` operator to compare the MD5 hash of your input against a stored hash. Can you get in without knowing the real password?

## Setup

```bash
docker compose up --build
```

Then visit: http://localhost:8080

## Solution

PHP's `==` (loose comparison) treats strings matching the pattern `0e[0-9]+` as scientific notation floats, so they all evaluate to `0`. This means any two MD5 hashes that both start with `0e` followed only by digits will be considered equal.

The stored hash is:
```
0e462097431906509019562988736854   ← md5("240610708")
```

You need to submit any string whose MD5 also starts with `0e[0-9]+`. Known working inputs:

| Input       | MD5 Hash                           |
|-------------|------------------------------------|
| `QNKCDZO`   | `0e830400451993494058024219903391` |
| `aabg7XSs`  | `0e087386482136013740957780965295` |
| `aabC9RqS`  | `0e041022518165728065344349536299` |

Any of these will bypass the check and reveal the flag.

## Why it works

```php
md5("QNKCDZO") == "0e462097431906509019562988736854"
// "0e830400451993494058024219903391" == "0e462097431906509019562988736854"
// PHP sees both as 0e... → converts to float 0.0 == 0.0 → true
```

The fix is to use strict comparison (`===`) instead of `==`.
