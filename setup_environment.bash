#!/bin/bash

# Pull in submodules
git pull --all
git submodule init
git submodule update --recursive

# Link submodules so that the main script knows how to find the packages
ln -sfv rtb_latency.py __main__.py
ln -sfv submodules/python-certifi/certifi certifi
ln -sfv submodules/chardet/chardet chardet
ln -sfv submodules/dnspython/dns dns
ln -sfv submodules/idna/idna idna
ln -sfv submodules/ipaddr-py/ipaddr.py ipaddr.py
ln -sfv submodules/ipwhois/ipwhois ipwhois
ln -sfv submodules/python-ping/ping.py ping.py
ln -sfv submodules/PyMySQL/pymysql pymysql
ln -sfv submodules/requests/requests requests
ln -sfv submodules/urllib3/urllib3 urllib3
