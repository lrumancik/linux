#!/bin/bash
#Attaches filter program to device and pins program and map
#Map used as bitmap for filtering IO based on starting region
#Pinned map is updated
#Program is detached and program/map unpinned
#Tests attempts to write to various parts of disk throughout

echo "Running tests for io_filter_map bpf program"

if [[ $# -ne 1 ]]; then
	echo "Please enter device as argument"
	exit 1
fi

TEST_DEV=$1
SECTOR_SIZE=512	#bytes per sector

#change to folder containing programs, 
#protect_gpt needs to be run in same folder as protect_gpt_kern.o
#TODO: update based on dir structure when added to xfstests
cd ..

#Load program:
./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --attach 1> /dev/null

if [[ $? -ne 0 ]]; then
	echo "Failed to load io_filter_map program"
	exit 1
fi


#Update map to prevent writes starting at sector 0
./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --update block 0 1 1> /dev/null

if [[ $? -ne 0 ]]; then
	echo "Failed to update map"
	./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --detach 1> /dev/null
	exit 1
fi


#Test: write to first block of disk
#	should fail
dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=0 count=1 oflag=direct &> /dev/null

if [[ $? -eq 0 ]]; then
	echo "Failed test: program allowed writing to first block of disk"
	./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --detach 1> /dev/null
	exit 1
fi

#Update map to allow writes starting at sector 0
./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --update allow 0 1 1> /dev/null

if [[ $? -ne 0 ]]; then
	echo "Failed to update map"
	./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --detach 1> /dev/null
	exit 1
fi


#Test: write to first block of disk
#	should pass
dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=0 count=1 oflag=direct &> /dev/null

if [[ $? -ne 0 ]]; then
	echo "Failed test: program blocked writing to first block of disk"
	./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --detach 1> /dev/null
	exit 1
fi


#Update map to prevent writes starting at sectors 101-105
./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --update block 100 5 1> /dev/null

if [[ $? -ne 0 ]]; then
	echo "Failed to update map"
	./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --detach 1> /dev/null
	exit 1
fi


#Test: write to block 103 of disk
#	should fail
dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=103 count=1 oflag=direct &> /dev/null

if [[ $? -eq 0 ]]; then
	echo "Failed test: program allowed writing to first block of disk"
	./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --detach 1> /dev/null
	exit 1
fi

#Detach program
./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --detach 1> /dev/null

if [[ $? -ne 0 ]]; then
	echo "Failed to detach protect_gpt program"
	exit 1
fi

#Test: write to block 103 of disk
#	should pass
dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=103 count=1 oflag=direct &> /dev/null

if [[ $? -ne 0 ]]; then
	echo "Failed test: program prevented writing to first block of disk after program detach"
	./io_filter_map $TEST_DEV io_filter${TEST_DEV//\//_} --detach 1> /dev/null
	exit 1
fi

echo "All tests passed."
exit 0
