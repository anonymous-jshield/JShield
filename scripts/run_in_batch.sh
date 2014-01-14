#!/bin/bash

echo arg1: directory to be detected
echo arg2: the list of file names you want to detect in arg1

dir_name=$1
file_name=$2

while read -r line
do
	./run.sh 3 $1/$line
done < $file_name
