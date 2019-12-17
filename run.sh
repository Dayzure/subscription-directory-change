#!/bin/bash
wget -q -O tmp.zip https://github.com/Dayzure/subscription-directory-change/raw/master/subscription-dir-change.zip && unzip tmp.zip && rm tmp.zip
./check-aad-deps.sh