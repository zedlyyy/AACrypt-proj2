# Advanced Applied Cryptography — Project 2

## Overview

Academic project exploring cryptographic techniques for protecting and processing data in a Java application backed by a MySQL database. The code includes encryption, digital signatures, integrity protection, and cryptographic indexing utilities, as well as dataset-loading and query-processing components.

## Database setup

```bash
docker run --name company-mysql -e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=company_db -p 3306:3306 -d mysql:latest
```
