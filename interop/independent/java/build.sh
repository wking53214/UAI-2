#!/bin/sh
# builds the receiver and self test into java/out (JDK 21, no dependencies)
cd "$(dirname "$0")" && rm -rf out && mkdir out && javac -Xlint:all -d out src/*.java 2>&1 | grep -v JAVA_TOOL_OPTIONS
