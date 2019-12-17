#!/bin/bash
cd ~/clouddrive
subscriptionId=$(az account show --query id | sed -e 's/^"//' -e 's/"$//')
workdir="dirchange-${subscriptionId}"
mkdir $workdir
cd $workdir
wget -q -O tmp.zip https://aka.ms/as/dirchange-package && unzip tmp.zip && rm tmp.zip
./check-aad-deps.sh