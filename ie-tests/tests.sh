#!/bin/bash
set +x 
TEST_FOLDER=$1
TEST_COMMAND=$2

echo ""

echo " "
echo "Changing folder to ${TEST_FOLDER}"

cd $TEST_FOLDER

echo " "
echo " Cleaning ..."
mvn clean

echo " "
echo " Running tests..."
# Run maven tests 
if [ -z "$TEST_COMMAND" ];
then 
    TEST_COMMAND="mvn test -fn"
fi

echo "Test command: $TEST_COMMAND"

$TEST_COMMAND

echo " "
echo " Finished."
