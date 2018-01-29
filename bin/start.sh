#!/usr/bin/env bash
set -o errexit

# The location of the java interpreter may be set explicitly with JAVA_EXE.
# Otherwise, JAVA_HOME is used.
# If JAVA_HOME is still undefined, simply use 'java'.
#JAVA_EXE="/usr/local/jdk8/bin/java"
if [ -z "$JAVA_EXE" ]
then
  if [ -z "$JAVA_HOME" ]
  then
    JAVA_EXE="java"
  else
    JAVA_EXE="$JAVA_HOME/bin/java"
  fi
fi

# The installation directory containing configuration and dependencies may be set explicitly with INSTALL_DIR.
# Otherwise, an attempt is made to discover the location of this start script.
#INSTALL_DIR=/var/attribyte/test

if [ -z "$INSTALL_DIR" ]
then
  DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
  INSTALL_DIR="$(dirname "$DIR")"
fi

if [ ! -d "$INSTALL_DIR/run" ]
then
  mkdir "$INSTALL_DIR/run"
fi

if [ -z ${1} ]
then
  echo "The server name must be specified to start"
  exit 1
else
  SERVER_NAME=${1}
  CONFIG_FILE="${SERVER_NAME}.config.sh"
fi

if [ ! -f "$INSTALL_DIR/config/$CONFIG_FILE" ]
then
	echo "The config file, $CONFIG_FILE, does not exist!"
	exit 1
fi

LOCAL_CONFIG="${INSTALL_DIR}/config/${SERVER_NAME}.local.props"
CONSOLE_LOG="${INSTALL_DIR}/logs/${SERVER_NAME}.log"
PID_FILE="${SERVER_NAME}.pid"
source "$INSTALL_DIR/config/$CONFIG_FILE"
CLASSPATH="${INSTALL_DIR}/target/${SERVER_JAR}:${INSTALL_DIR}/target/dependency/*"

if [ -z ${2} ]
then
  DEBUG="false"
else
  DEBUG="debug"
fi

if [ -f "$INSTALL_DIR/run/$PID_FILE" ]
then
	echo "The ${SERVER_NAME} server appears to be running!"
	exit 0
fi

if [ $DEBUG == "debug" ]
then
 if [ -f "$LOCAL_CONFIG" ]; then
  $JAVA_EXE -cp "${CLASSPATH}" -Dserver.debug=true -Dserver.install.dir="$INSTALL_DIR" $SERVER_CLASS $LOCAL_CONFIG
 else
  $JAVA_EXE -cp "${CLASSPATH}" -Dserver.debug=true -Dserver.install.dir="$INSTALL_DIR" $SERVER_CLASS
 fi
else
 if [ -f "$LOCAL_CONFIG" ]; then
  nohup $JAVA_EXE -cp "${CLASSPATH}" -Dserver.install.dir="$INSTALL_DIR" $SERVER_CLASS $LOCAL_CONFIG 1> $CONSOLE_LOG 2>&1 &
 else
  nohup $JAVA_EXE -cp "${CLASSPATH}" -Dserver.install.dir="$INSTALL_DIR" $SERVER_CLASS 1> $CONSOLE_LOG 2>&1 &
 fi
 echo $! > $INSTALL_DIR/run/$PID_FILE
fi
