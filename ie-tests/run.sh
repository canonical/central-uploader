#!/bin/bash

function run_tests() {
    echo "START TEST"
    LABEL=$1
    TEST_COMMAND=$2
    IE_FOLDER=$(pwd)

    FOLDER="${IE_FOLDER}/.."

    DATE=$(date +%Y%m%dH%HM%M)
    COMMIT=$(git rev-parse --short HEAD)
    SAFE_LABEL=${LABEL//[^a-zA-Z0-9._-]/_}

    LOG_NAME=${DATE}_${SAFE_LABEL}_${RANDOM}_test

    mkdir -p "${IE_FOLDER}/logs"

    STD_OUT="${IE_FOLDER}/logs/${LOG_NAME}.out"
    STD_ERR="${IE_FOLDER}/logs/${LOG_NAME}.err"

    # populate the error file
    echo "" >>$STD_ERR

    echo "***************************************" >$STD_OUT
    echo "     INTEGRATION TESTS" >>$STD_OUT
    echo "***************************************" >>$STD_OUT
    echo "" >>$STD_OUT
    echo "Date: ${DATE}" >>$STD_OUT
    echo "Label: ${LABEL}" >>$STD_OUT
    echo "Commit: ${COMMIT}" >>$STD_OUT
    echo "LogName: ${LOG_NAME}" >>$STD_OUT
    echo "" >>$STD_OUT
    echo "***************************************" >>$STD_OUT
    echo "" >>$STD_OUT

    FORMAT_TIME="\n***************************************\nTIMINGS:\n%E real\n%U user\n%S sys"

    echo "Before running the test!"
    ./tests.sh "${FOLDER}" "${TEST_COMMAND}" >>$STD_OUT 2>$STD_ERR

    echo "***************************************" >>$STD_OUT
}

LABEL=$1
TEST_COMMAND=$2

echo "Label: ${LABEL}"
echo "Command: ${TEST_COMMAND}"
run_tests "${LABEL}" "${TEST_COMMAND}"
