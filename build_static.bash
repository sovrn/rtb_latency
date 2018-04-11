#!/bin/bash

zip -9\
  --exclude \*.pyc \*.rst \*.txt \*.bat Makefile\
  --recurse-paths\
  tmp.zip\
  certifi\
  chardet\
  dns\
  idna\
  ipwhois\
  pymysql\
  requests\
  urllib3\
  __main__.py\
  ipaddr.py\
  ping.py\

cat - tmp.zip <<< '#!/usr/bin/env python' > rtb_latency.pyz
chmod -v a+rx rtb_latency.pyz
rm -v tmp.zip
