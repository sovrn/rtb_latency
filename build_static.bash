#!/bin/bash -ev

# Ensure that the environment has all the submodules and symlinks in place
source setup_environment.bash

# Create temporary zip file that conatins rtb_latency and all its dependencies
zip -9\
  --exclude \*.pyc \*.rst \*.txt \*.bat Makefile\
  --recurse-paths\
  tmp.zip\
    certifi\
    chardet\
    dns\
    idna\
    ipwhois\
    netaddr\
    pymysql\
    requests\
    urllib3\
    __main__.py\
    ipaddr.py\
    ping.py\

# Prepend shebang to zip file so Python will execute it
cat - tmp.zip <<< '#!/usr/bin/env python2' > rtb_latency.pyz
# Set Permissions
chmod -v a+rx rtb_latency.pyz
# Remove temporary file
rm -v tmp.zip
