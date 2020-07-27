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

#Tests attempts to write to various parts of disk
#While program is attached, writes to GPT should be blocked while all other regions allowed
test_device() {
	echo "Running ${TEST_NAME}"
	
	GPT_SIZE=34	#number sectors in GPT
	SECTOR_SIZE=512	#bytes per sector

	#change to folder containing programs, 
	#protect_gpt needs to be run in same folder as protect_gpt_kern.o
	cd "$SRCDIR"
	
	#Load program:
	./protect_gpt "$TEST_DEV" "protect_gpt${TEST_DEV//\//_}" --attach 1> /dev/null

	#Test: write to first GPT_SIZE blocks
	#	should fail
	dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE count=$GPT_SIZE oflag=direct &> /dev/null 
	if [[ $? -eq 0 ]]; then
		echo "Failed test: program allowed writing to GPT"
	fi

	#Test: write to last block of GPT and first block after GPT
	#	should fail
	dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=$(($GPT_SIZE-1)) count=2 oflag=direct &> /dev/null
	if [[ $? -eq 0 ]]; then
		echo "Failed test: program allowed writing to last block of GPT"
	fi

	#Test: write to block after first GPT_SIZE blocks
	#	should pass
	dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE seek=$GPT_SIZE count=1 oflag=direct &> /dev/null
	if [[ $? -ne 0 ]]; then
		echo "Failed test: program blocked writing to non-GPT sector"
	fi

	#Detach program
	./protect_gpt "$TEST_DEV" "protect_gpt${TEST_DEV//\//_}" --detach 1> /dev/null
	
	#Test: write to first GPT_SIZE blocks
	#	should pass
	dd if=/dev/zero of="$TEST_DEV" bs=$SECTOR_SIZE count=$GPT_SIZE oflag=direct &> /dev/null 
	if [[ $? -ne 0 ]]; then
		echo "Failed test: program blocked writing to GPT after detach"
	fi
	
	echo "Test complete"
}

