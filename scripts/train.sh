#!/bin/bash

#test flag
i=`expr $# - 3`
flag=0
echo $i
echo "${i}"
echo $(($i%2))
echo ${!#}
i=0
pair_num=`expr $# - 2`
for p in $@
do 
	if [ $i -ge $pair_num ]; then
		break
	fi
	if [ $(($i%2)) -eq 0 ]; then
	#check if the argument is directory
		if [ ! -d "$p" ]; then
			echo "Parameters Error [DIRECTORY]"
			exit 1
		fi	
	else
		tmp=$(echo $p|bc 2>/dev/null)
		if [ -z $tmp ]; then
			echo 'Parameteres Error [FLAG]'
			exit 1
		fi
		if [ $tmp -eq 0 ]; then
			echo "Parameters Error [FLAG]"
			exit 1
		fi
		if [ "$p" -ne "1" ] && [ "$p" -ne "0" ]; then
			echo "Parameters Error [FLAG]"
			exit 1
		fi

	fi
	
	echo "$p"
	i=`expr $i + 1`
done
#test validation sets
i=`expr $# - 1`
echo $i
while([ "$i" -le "$#" ])
do
	if [ ! -d "${!i}" ]; then
		echo "Parameters Error [VALIDATION]"
		exit 1
	fi
	i=`expr $i + 1`
done

echo "Parameters are valid"
echo "Start to Generate Source Codes"
i=1
for p in $@
do
	if [ -d $p ]; then
		${JSHIELD_CLA_DIR}/scripts/generate_source_codes.sh $p
	fi
done

#./run 1 $@
