#!/bin/bash

TEST_FOLDER=$1

echo " "
echo "Changing folder to ${TEST_FOLDER}"

cd $TEST_FOLDER

echo " "
echo " Cleaning ..."
mvn clean

echo " "
echo " Running tests..."
mvn test -fn 
# -Dhadoop.version=3.3.6-ubuntu1

echo " "
echo " Finished."
