#!/bin/bash

BIN=/usr/lib/chromium/chromium
DIR=chromium

rm -rf $DIR
mkdir $DIR

ldd $BIN > $DIR/README

cp $BIN $DIR

ldd $BIN | grep '=>' | awk '{print $3}' | xargs -I{} cp {} $DIR
