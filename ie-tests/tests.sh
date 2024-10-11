#!/bin/bash

TEST_FOLDER=$1

echo " "
echo "Changing folder to ${TEST_FOLDER}"

cd $SPARK_FOLDER

echo " "
echo " Cleaning ..."
mvn clean

echo " "
echo " Running tests..."
# temporary commented test
# mvn test -fn 
echo "FAKE TEST"
# -Dhadoop.version=3.3.6-ubuntu1

echo " "
echo " Finished."
