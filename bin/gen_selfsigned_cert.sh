#!/usr/bin/env bash
keytool -keystore ../keystore/selfsigned.jks -alias selfsigned -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -genkey -dname "CN=localhost" -validity 3650