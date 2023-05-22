#!/bin/bash

# Tested with ProVerif version 2.04
pv=proverif

title="ap"
ap_f="./model/Apple_pair.pv"
ap_f_fixed="./model/Apple_pair_fixed_id_sharing.pv"

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
		if [[ $line == *"event(recv_peripheral(id)) ==> event(send_central(id))"* ]]; then
			property="A1"
		fi
		if [[ $line == *"event(recv_central(id)) ==> event(send_peripheral(id))"* ]]; then
			property="A2"
		fi
	done

	# Some space before the next entry
	echo ""
}

echo "Verifying Apple pair confidentiality."
prepare "1" "ap"
cat $ap_f > $tmp_f
analyze

echo "Verifying Apple pair confidentiality of the fixed protocols. (simplified protocol model)"
prepare "2" "ap_fixed"
cat $ap_f_fixed > $tmp_f
analyze

