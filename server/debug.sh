#!/bin/bash

# how to run notary locally, for debugging purpose

#./convergence-notary.py -p 10080 -s 10443 --proxy-port 14242 -c mynotary.pem -k mynotary.key -f -d --log-file convergence.log --pid-file convergence.pid --db-path convergence.db

# or with turned off SSL layer:
#./convergence-notary.py --no-https -p 10080 -s 10443 --proxy-port 14242 -c mynotary.pem -k mynotary.key -f -d --log-file convergence.log --pid-file convergence.pid --db-path convergence.db

./convergence-notary.py --no-https -p ${1}0080 -s ${1}0443 --proxy-port ${1}4242 -c mynotary.pem -k mynotary.key -f -d --log-file convergence.log --pid-file convergence.pid --db-path convergence.db
