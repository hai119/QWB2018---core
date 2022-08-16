#!/bin/sh
gcc ROP.c -static -masm=intel -g -o ROP
cp ROP core/ROP 
cd core
./gen_cpio.sh core.cpio
mv core.cpio ..
cd ..
./start.sh
