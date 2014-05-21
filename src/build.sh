#!/bin/bash
##########################################################################
# Script for building/compiling the bouncer applications in course ik2213.
# Note to students: you will have to adapt your application to this script
# The script name must not be changed, no parameters will be set.
# Tip: use comand 'export' if you need to set environment variables.
# Tip: use a makefile or ant for building.
# -----------------------------------------------------------------------
# Project - Packet Bouncer
# 11-May-2014
# Ganapathy Raman Madanagopal <grma@kth.se>
# Tien Thanh Bui <ttbu@kth.se>
##########################################################################
THISFILE=${0##*/}
PID=$$
##########################################################################

# To Run the Make File
make

# From Completing the Make Exit
exit 0
