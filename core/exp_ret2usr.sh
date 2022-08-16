#!/bin/sh
gcc ret2usr.c -static -masm=intel -g -o ret2usr
cp ret2usr core/ret2usr 
cd core
./gen_cpio.sh core.cpio
mv core.cpio ..
cd ..
./start.sh
