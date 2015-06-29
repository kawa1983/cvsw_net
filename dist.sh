#!/bin/sh

VERSION=`uname -r`

if expr ${VERSION} : ".*431.*el6" > /dev/null; then
	echo RHEL6.5
elif expr ${VERSION} : ".*504.*el6" > /dev/null; then
	echo RHEL6.6
elif expr ${VERSION} : ".*el7" > /dev/null; then
	echo RHEL7
elif expr ${VERSION} : ".*fc" > /dev/null; then
	echo Fedora
elif expr ${VERSION} : ".*generic" > /dev/null; then
	echo Ubuntu
fi

