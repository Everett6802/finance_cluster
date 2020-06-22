#!/bin/bash

SIMULATOR_ROOT="/simulator/BUILD"
SIMULATOR_SCRIPT_FOLDERPATH="$SIMULATOR_ROOT/scripts"
FAKE_ACSPT_SCRIPT_FILENAME="fake_acspt.sh"


check_root() 
{
  if [ "$UID" -ne 0 ] ; then
     echo "Please run the script as root"
     exit 1    # non-root error
  fi
}

check_param() 
{
  if [ $# -lt 1 ]; then
      Usage
      exit 1  # incorrect param error
  fi
}

usage() 
{
    echo "Please input the correct argument"
    echo "  start : Start the fake access point"
    echo "  stop  : Stop the fake access point"
}

start_fake_acspt()
{
	cd $SIMULATOR_SCRIPT_FOLDERPATH
	./$FAKE_ACSPT_SCRIPT_FILENAME up
}

stop_fake_acspt()
{
	cd $SIMULATOR_SCRIPT_FOLDERPATH
	./$FAKE_ACSPT_SCRIPT_FILENAME clean
}

if [ ! -d $SIMULATOR_ROOT ] ; then
	echo "Simulator root folder[$SIMULATOR_ROOT] does NOT exist"
	exit 1
fi

# entry point
check_root
check_param "$@"

case "$1" in
    start)
        start_fake_acspt
    ;;
    stop)
        stop_fake_acspt
    ;;
    *)
        echo "Unknown command: $1. Exiting now..."
        usage
        exit 1
    ;;
esac

# cd $SIMULATOR_SCRIPT_FOLDERPATH
# ./$FAKE_ACSPT_SCRIPT_FILENAME $1
# $SIMULATOR_ROOT/$FAKE_ACSPT_SCRIPT_FILENAME $1
