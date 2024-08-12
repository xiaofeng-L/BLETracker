#!/bin/bash
file_path="$1"

sed -i 's/session_equiv/trace_equiv/g' $file_path
echo "replace session_equiv with trace_equiv"