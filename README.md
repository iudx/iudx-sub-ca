# IUDX-Sub-CA

![ISC license](https://img.shields.io/badge/license-ISC-blue.svg)

# Introduction

IUDX sub-CA software allows organizations to issue certificates to their employees.
This allows employees to get certificates to access [IUDX](https://www.iudx.org.in) services.

The sub-CAs must have a valid certificate from [IUDX Certificate Authority (CA)](https://ca.iudx.org.in). 

# Setup on docker

#### Please install:

- docker
- docker-compose

#### Then run:

```bash
git clone https://github.com/iudx/iudx-sub-ca
cd iudx-sub-ca
./install.docker
```

# Setup on OpenBSD 

```bash
ftp -o - https://iudx.org.in/install/subca | sh
```

# After install 

- The setup will generate a self-signed certificate in **cert/** folder. Please update the **cert/** folder with real certificates and keys.
 
- Configure the [subca.py](https://github.com/iudx/iudx-sub-ca/blob/master/server/conf/subca.py "subca.py") in **server/conf/** directory according to your organization's credentials and details.

# To manage employees in your organization 

- Update the server/employee_db.py and restart the server

# To get docker logs

```bash
cd docker && ./logs # OR directly use `docker logs iudx-sub-ca`
```
