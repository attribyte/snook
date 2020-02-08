#!/usr/bin/env bash
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

if [ -z "$INSTALL_DIR" ]
then
  DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
  INSTALL_DIR="$(dirname "$DIR")"
fi

SNOOK_JAR="snook-0.1.0-SNAPSHOT.jar"
COMMAND_CLASS="org.attribyte.snook.auth.HMACToken"
CLASSPATH="${INSTALL_DIR}/target/${SNOOK_JAR}:${INSTALL_DIR}/target/dependency/*"

$JAVA_EXE -cp "${CLASSPATH}" $COMMAND_CLASS $1 $2 $3 $4

