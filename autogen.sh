#!/bin/bash

mkdir -p m4
autoreconf -fi
rm -Rf autom4te*.cache config.h.in~
