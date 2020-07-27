#!/bin/bash
#!/bin/bash
# SPDX-License-Identifier: GPL-3.0+
# Copyright (C) 2020 Leah Rumancik
#
# Tests eBPF IO filter program type via protect_gpt sample program
# in commit:
# TODO: add commit

# For a commit, use the first 12 characters of the commit hash and the one-line
# commit summary:
#
# Regression test for commit efd4b81abbe1 ("blk-stat: fix blk_stat_sum() if all
# samples are batched").

. tests/block/rc

DESCRIPTION="check BPF IO filter program protects GPT"

#test completes quickly
QUICK=1

# TODO: if this test can be run for both regular block devices and zoned block
# devices, uncomment the line below.
# CAN_BE_ZONED=1

# TODO: if this test has any extra requirements, it should define a requires()
# function. If the test cannot be run, requires() should set the $SKIP_REASON
# variable. Usually, requires() just needs to check that any necessary programs
# and kernel features are available using the _have_foo helpers. If requires()
# sets $SKIP_REASON, the test is skipped.
# requires() {
# 	_have_foo
# }

#Attaches filter program to device and pins program and map
#Map used as bitmap for filtering IO based on starting region
#Pinned map is updated
#Program is detached and program/map unpinned
#Tests attempts to write to various parts of disk throughout
test_device() {
	echo "Running ${TEST_NAME}"
	
	#change to folder containing programs, 
	#protect_gpt needs to be run in same folder as protect_gpt_kern.o
	cd "$SRCDIR"

	SECTOR_SIZE=512	#bytes per sector

	#Load program:
	./io_filter_map "$TEST_DEV" "io_filter${TEST_DEV//\//_}" --attach 1> /dev/null

	#Update map to prevent writes starting at sector 0
	./io_filter_map "$TEST_DEV" "io_filter${TEST_DEV//\//_}" --update block 0 1 1> /dev/null

	#Test: write to first block of disk
	#	should fail
	dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=0 count=1 oflag=direct &> /dev/null
	if [[ $? -eq 0 ]]; then
		echo "Failed test: program allowed writing to first block of disk"
	fi

	#Update map to allow writes starting at sector 0
	./io_filter_map "$TEST_DEV" "io_filter${TEST_DEV//\//_}" --update allow 0 1 1> /dev/null

	#Test: write to first block of disk
	#	should pass
	dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=0 count=1 oflag=direct &> /dev/null
	if [[ $? -ne 0 ]]; then
		echo "Failed test: program blocked writing to first block of disk"
	fi

	#Update map to prevent writes starting at sectors 101-105
	./io_filter_map "$TEST_DEV" "io_filter${TEST_DEV//\//_}" --update block 100 5 1> /dev/null

	#Test: write to block 103 of disk
	#	should fail
	dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=103 count=1 oflag=direct &> /dev/null
	if [[ $? -eq 0 ]]; then
		echo "Failed test: program allowed writing to first block of disk"
	fi

	#Detach program
	./io_filter_map "$TEST_DEV" "io_filter${TEST_DEV//\//_}" --detach 1> /dev/null

	#Test: write to block 103 of disk
	#	should pass
	dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=103 count=1 oflag=direct &> /dev/null
	if [[ $? -ne 0 ]]; then
		echo "Failed test: program prevented writing to first block of disk after program detach"
	fi
	
	echo "Test complete"
}

