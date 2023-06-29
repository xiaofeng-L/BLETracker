#!/bin/bash

# Tested with ProVerif version 2.04
# pv=proverif
pv="/data/xiaofeng/tools/proverif2.04/proverif"
title="sp"
sp_f="./model/C1_Samsung_pair.pv"
sp_f_fixed="./model/C1_Samsung_pair_fixed.pv"


prepare () {
	curr_num="$1"
	curr_name="$2"
	outdir="results-$title-$1-$2"
	mkdir -p $outdir
	tmp_f="$outdir/model.pv"
	out_f="$outdir/output.txt"
	options="-html $outdir"
}

# Analyze the current $tmp_f file and store the results;
analyze () {
	time $pv $options $tmp_f | tee $out_f | grep RESULT

	grep "RESULT.*false" $out_f | while read -r line ; do
		# property=$(echo $line | awk -F '[([]' '{ print $2 }')
		if [[ $line == *"attacker(s[])"* ]]; then
			property="C1"
		fi
	done

	# Some space before the next entry
	echo ""
}


echo "Verifying Samsung pair confidentiality."
prepare "1" "sp"
cat $sp_f > $tmp_f
analyze

echo "Verifying Samsung pair confidentiality of the fixed protocols."
prepare "2" "sp_fixed"
cat $sp_f_fixed > $tmp_f
analyze
