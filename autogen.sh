#!/bin/bash

libtoolize
autoreconf -fi;
rm -Rf autom4te*.cache config.h.in~
