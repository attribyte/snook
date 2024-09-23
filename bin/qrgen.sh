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

SNOOK_JAR="snook-0.2.8.jar"

CLASSPATH="${INSTALL_DIR}/target/${SNOOK_JAR}:${INSTALL_DIR}/target/dependency/*"
$JAVA_EXE -cp "${CLASSPATH}" -Dserver.install.dir="$INSTALL_DIR" org.attribyte.snook.QRCode $1 $2 $3 $4 $5 $6 $7
