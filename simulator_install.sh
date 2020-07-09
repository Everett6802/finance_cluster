#!/bin/bash

SIMULATOR_ROOT="/simulator"
SIMULATOR_PACKAGE="/dev/shm/simulator"


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
    echo "  <madsz_filepath> : MadSZ filepath (Ex: /home/lab/simulator-v5.2-23-u1804.tar.gz)"
}

# entry point
check_root
check_param "$@"

# while getopts ":f:" param; do
#   case "${param}" in
#     f)
#       simulator_source_filepath=${OPTARG}
#       ;;
#     *)
#       usage
#       ;;
#   esac
# done

if [ ! -f $1 ] ; then
  echo "Simulator package[$1] does NOT exist"
  exit 1
fi

simulator_source_filename=$(basename $1)

# Remove the old simulator if exists
rm -rf $SIMULATOR_PACKAGE 
rm -rf $SIMULATOR_ROOT
# Install the new simulator
mkdir -p $SIMULATOR_PACKAGE
cp $1 $SIMULATOR_PACKAGE
cd $SIMULATOR_PACKAGE
tar xfJ $simulator_source_filename
ln -s $SIMULATOR_PACKAGE $SIMULATOR_ROOT


# cd $SIMULATOR_SCRIPT_FOLDERPATH
# ./$FAKE_ACSPT_SCRIPT_FILENAME $1
# $SIMULATOR_ROOT/$FAKE_ACSPT_SCRIPT_FILENAME $1
