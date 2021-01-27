#!/bin/sh

DIR=`dirname $0`
SCRIPT="${DIR}/cve_db.pl"
if [ -x $SCRIPT ]; then
   $SCRIPT --update > /dev/null 2>&1
   $SCRIPT --dump
fi
