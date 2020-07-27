#!/bin/bash

#TODO: update this number
#TODO: also update number in .out file
TEST_NUM_GPT="026"
TEST_NUM_MAP="027"

cp /vtmp/samples/bpf/io_testing/blktests_protect_gpt.sh "/root/blktests/tests/block/$TEST_NUM_GPT"
cp /vtmp/samples/bpf/io_testing/blktests_protect_gpt.out "/root/blktests/tests/block/$TEST_NUM_GPT.out"
cp /vtmp/samples/bpf/protect_gpt_kern.o /root/blktests/src/
cp /vtmp/samples/bpf/protect_gpt /root/blktests/src/

cp /vtmp/samples/bpf/io_testing/blktests_test_map.sh "/root/blktests/tests/block/$TEST_NUM_MAP"
cp /vtmp/samples/bpf/io_testing/blktests_test_map.out "/root/blktests/tests/block/$TEST_NUM_MAP.out"
cp /vtmp/samples/bpf/io_filter_map_kern.o /root/blktests/src/
cp /vtmp/samples/bpf/io_filter_map /root/blktests/src/

cd /root/blktests
./check "block/$TEST_NUM_GPT" "block/$TEST_NUM_MAP"
