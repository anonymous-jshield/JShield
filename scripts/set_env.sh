#/bin/bash
echo "Remember to change JAVA_HOME environment"
echo "Please change database settings if you would use train engine"
JAVA_HOME=`whoami`/software/jdk1.7.0_07
AST_HOME=../
#database info needs to be re-configured 
#based on your dababase account
echo "db_user=`whoami`" >> config.properties
echo "db_password=000000" >> config.properties
echo "db_name=NO_DB" >> config.properties
echo "db_url=localhost" >> config.properties


#=========================NO CHANGE=====================================

JAVA_PATH="$JAVA_HOME"
echo "tfiles_dir=${AST_HOME}/trained_file_names/" | sed 's/\//\/\//g'  > config.properties
echo "feature_dir=${AST_HOME}/feature_sets/" | sed 's/\//\/\//g'  >> config.properties
echo "blist_dir=${AST_HOME}/feature_sets/" | sed 's/\//\/\//g' >> config.properties

#EVENTTRI_PATH=/home/xpan/WebKit-r10xxxx/Tools/Scripts/run-launcher
PATH=${JAVA_PATH}/bin:$PATH
REPORT_GEN_HOME="$AST_HOME"/ReportGenerator
#export EVENTTRI_PATH
#echo $EVENTTRI_PATH
#echo $JAVA_PATH
#echo $PATH
#export EVENTTRI_PATH
export JAVA_PATH
export JAVA_HOME
export PATH
export AST_HOME
export REPORT_GEN_HOME
