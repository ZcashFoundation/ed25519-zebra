#!/bin/bash

# Script to run in order to compile a JAR with the Ed25519 JNI libraries from Rust.
# Assumes SciJava's NativeLoader will be used.
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  nativeDir="ed25519jni/natives/linux_64"
  nativeSuffix="so"
elif [[ "$OSTYPE" == "darwin"* ]]; then
  nativeDir="ed25519jni/natives/osx_64"
  nativeSuffix="dylib"
else
  echo "JNI is unsupported on this OS. Exiting."
  exit 1
fi

useDebug="0"
while getopts ":d" opt; do
  case $opt in
    d)
      useDebug="1"
      ;;
  esac
done

# Give priority to release directory, unless a debug flag was passed in.
mkdir -p ${nativeDir}
if [ ${useDebug} -eq "1" ]; then
  mode=debug
else
  mode=release
fi

if [[ -d ed25519jni/target/rust/${mode} ]] ; then
  cp -f ed25519jni/target/rust/${mode}/libed25519jni.a ${nativeDir}
  cp -f ed25519jni/target/rust/${mode}/libed25519jni.${nativeSuffix} ${nativeDir}
else
  echo "Unable to obtain required libed25519jni ${mode} libraries. Exiting."
  exit 1
fi
