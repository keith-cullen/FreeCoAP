#!/bin/bash

start=$(date +%N)
./test_coap_msg
end=$(date +%N)
diff=$((end-start))
echo "start: ${start}, end: ${end}, diff: ${diff}"
