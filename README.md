# IUDX-Sub-CA

![ISC license](https://img.shields.io/badge/license-ISC-blue.svg)


Quickstart
========== 

# Please install the following dependencies manually, skip if already installed

	- docker
	- docker-compose
# Setup

    git clone https://github.com/iudx/iudx-sub-ca
	cd iudx-sub-ca
	./install-sub-CA <cert/sub-ca.crt> <cert/sub-ca.key>


- NOTE: Either put your sub-ca.crt and sub-ca.key in **cert/** directory or give appropriate file path to install-sub-CA as arguments. 
- Configure the [conf.py](https://github.com/iudx/iudx-sub-ca/blob/master/server/conf.py "conf.py") in **server/** directory according to your organization's credentials and details.

# For creating Self-Signed Certificates (for testing)
	
    cd scripts && ./create-cert

# Setup with Self-Signed Certificate and Key

    cd iudx-sub-ca
    ./install-self-signed-sub-CA

# To insert an employee, use insert_employee script in **scripts/** directory

    cd scripts/ && chmod a+x ./insert_employee
    ./insert_employee <email-id> <firstname> <lastname> <title> <certificate-class> 

# To see all inserted employees, use show_employees script in **scripts/** directory

    cd scripts/ && chmod a+x ./show_employees
    ./show_employees

# To get docker logs

    cd docker && ./logs # OR directly use `docker logs iudx-sub-ca`
