#!/bin/bash

#This script will start WebKit and store the output to ../ground/filename.src

full_name=$1
file_name=`basename $1`

#$EVENTTRI_PATH $1 > $AST_HOME/ground/${file_name}.src 2>/dev/null
$EVENTTRI_PATH $1 > $AST_HOME/ground/${file_name}.src

