#!/bin/bash

if [ ! -d $1 ]; then
	echo "directory $1 does not exist"
	exit 1
fi

rm `find $1 -name "*.src" -o  -name "list"` 2>/dev/null
#rs=$(find $1 -name "*.src" -o  -name "list")
#echo $rs
#if [ ! -z $rs ]; then
#	echo "remove"
#	rm $rs
#fi

ls $1 > $JSHIELD_CLA_DIR/ground/list
mv $JSHIELD_CLA_DIR/ground/list $1/list

$JSHIELD_CLA_DIR/scripts/vxargs.py -y -P 40 -a $1/list -t 10 -o $JSHIELD_CLA_DIR/ground/logs/ bash -c "$EVENTTRI_PATH {} >$1/{}.src 2>/dev/null"
#~/vxargs.py -y -P 40 -a list -t 50 -o ../logs/ bash -c "~/WebKit-r10xxxx/Tools/Scripts/run-launcher {} >../ActivexObject_info/{}.src 2>/dev/null"

