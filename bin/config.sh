#!/usr/bin/env bash
VERSION="0.1.0"
#JAVA_EXE="/usr/local/jdk8/bin/java"
#INSTALL_DIR=/var/attribyte/test
SERVER_NAME="snook"
SERVER_DESCRIPTON="Proxy Server"
SERVER_CLASS="org.attribyte.snook.ProxyServer"
PIDFILE="${SERVER_NAME}.pid"

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

LOCAL_CONFIG="${INSTALL_DIR}/config/local.props"
CONSOLE_LOG="${INSTALL_DIR}/logs/server.log"