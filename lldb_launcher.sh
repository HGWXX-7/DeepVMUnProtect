#!/bin/bash

connect="gdb-remote 9707\n"
version="version\n"
command=$connect$version$version$version$version


export PYTHONHOME=/home/morangeous/Android/Sdk/ndk/22.0.7026061/toolchains/llvm/prebuilt/linux-x86_64/install/python3
echo -e $command | /home/morangeous/Android/Sdk/ndk/22.0.7026061/toolchains/llvm/prebuilt/linux-x86_64/bin/lldb
#echo -e "gdbser\n" |