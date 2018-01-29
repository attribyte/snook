#!/usr/bin/env bash

# The installation directory containing configuration and dependencies may be set explicitly with INSTALL_DIR.
# Otherwise, an attempt is made to discover the location of this start script.
#INSTALL_DIR=/var/attribyte/test

if [ -z "$INSTALL_DIR" ]
then
  DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
  INSTALL_DIR="$(dirname "$DIR")"
fi

if [ -z ${1} ]
then
  echo "The server name must be specified to stop"
  exit 1
else
  SERVER_NAME=${1}
fi

PID_FILE="${SERVER_NAME}.pid"

if [ ! -f "$INSTALL_DIR/run/$PID_FILE" ]
then
	echo "The ${SERVER_NAME} server does not seem to be running!"
	exit 1
fi

PID=$(cat $INSTALL_DIR/run/$PID_FILE)
echo "Stopping ${SERVER_NAME} $PID"

ATTEMPTS_LEFT=30
while [ $ATTEMPTS_LEFT -gt 0 ]
do
    kill $PID 2>/dev/null
    if [ $? -eq 1 ]
    then
        echo "Stopped ${SERVER_NAME} $PID normally"
        rm $INSTALL_DIR/run/$PID_FILE
        break
    fi
    ATTEMPTS_LEFT=$(($ATTEMPTS_LEFT - 1))
    sleep 1
done

#Kill
if [ $ATTEMPTS_LEFT -eq 0 ]
then
    echo "Killed ${SERVER_NAME} $PID!"
    kill -9 $PID
    rm $INSTALL_DIR/run/$PID_FILE
    exit 1
fi