#!/bin/bash
javac -classpath ../libs/aspectjtools-1.6.5.jar:../libs/mysql-connector-java-5.1.21-bin.jar:../libs/org.eclipse.wst.jsdt.core_1.1.101.v201108151912.jar:../libs/osgi-3.3.0-v20070530.jar:../libs/runtime-3.0m8.jar:../libs/commons-httpclient-3.1.jar:../libs/commons-logging-1.0.4.jar:../libs/commons-codec-1.3.jar:$JAVA_HOME/lib/ -d ../bin/ ../src/JShield.java ../src/nb_ast/* ../src/blacklist/BlackList.java

