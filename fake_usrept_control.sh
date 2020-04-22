#!/bin/bash

SIMULATOR_ROOT="/simulator/BUILD"
SIMULATOR_BIN_FOLDERPATH="$SIMULATOR_ROOT/bin"
SIMULATOR_CONF_FOLDERPATH="$SIMULATOR_ROOT/conf"
FAKE_USREPT_EXE_FILENAME="fake_usrept"
FAKE_USREPT_CONF_FILENAME="fake_usrept.conf"
FAKE_USREPT_CONF_FILEPATH="$SIMULATOR_CONF_FOLDERPATH/$FAKE_USREPT_CONF_FILENAME"


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
    echo "  start : Start the fake user endpoint"
    echo "  stop  : Stop the fake user endpoint"
}

start_fake_usrept()
{
	 cd $SIMULATOR_BIN_FOLDERPATH
	 rm -f nohup.out
	 ln -s /dev/null nohup.out
	 nohup ./$FAKE_USREPT_EXE_FILENAME -c $FAKE_USREPT_CONF_FILEPATH > /dev/null 2>&1 &
}

stop_fake_usrept()
{
	killall -q $FAKE_USREPT_EXE_FILENAME
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
        start_fake_usrept
    ;;
    stop)
        stop_fake_usrept
    ;;
    *)
        echo "Unknown command: $1. Exiting now..."
        usage
        exit 1
    ;;
esac
