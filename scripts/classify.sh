#!/bin/bash

if [ $# == 0 ];then
	echo "Error: input file name please"
	exit 1
fi

if [ ! -f $1 ]; then
	echo 'File Does Not Exist '
	exit 1
fi


full_name=$1
file_name=`basename $1`
dir_name=`dirname $1`

#EVENTTRI_PATH should be defined
$AST_HOME/scripts/start_webkit.sh $1 &
pid=$!
sleep 10
kill -9 $pid

rs=`python $AST_HOME/scripts/rewrite.py $AST_HOME/ground/$file_name.src`
#echo $rs
NO='N'
YES='Y'
NO_CHANGE='S'
if [ $rs == $NO ];then
	echo "Can't find files ${1}"
elif [ $rs = $YES ]; then
	rs=`$AST_HOME/scripts/run.sh 3 $AST_HOME/ground/rw_${file_name}.src`
	echo $rs
elif [ $rs = $NO_CHANGE ]; then
	rs=`$AST_HOME/scripts/run.sh 3 $AST_HOME/ground/${file_name}.src`
	echo $rs
fi
