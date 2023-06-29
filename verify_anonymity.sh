#!/bin/bash
# Tested with ProVerif version 2.04
pv="/data/xiaofeng/tools/proverif2.04/proverif"
title="anonymity"
A1="./model/A1_Apple_broadcast.pv"
A2="./model/A2_Samsung_broadcast_AdvAddr.pv"
A3="./model/A3_Samsung_broadcast_ID.pv"
A4="./model/A4_Samsung_broadcast_signature.pv"
A5="./model/A5_Samsung_broadcast_pubkey.pv"

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
		if [[ $line == *"Observational equivalence"* ]]; then
			property="A"
		fi
	done

	# Some space before the next entry
	echo ""
}


echo "Verifying Apple broadcast anonymity: public key."
prepare "1" "Apple_pubkey"
cat $A1 > $tmp_f
analyze

echo "Verifying Samsung broadcast anonymity: BLE advertisement address."
prepare "2" "Samsung_AdvAddr"
cat $A2 > $tmp_f
analyze

echo "Verifying Samsung broadcast anonymity: unique ID."
prepare "3" "Samsung_ID"
cat $A3 > $tmp_f
analyze

echo "Verifying Samsung broadcast anonymity: signature."
prepare "4" "Samsung_signature"
cat $A4 > $tmp_f
analyze

echo "Verifying Samsung broadcast anonymity: public key."
prepare "5" "Samsung_pubkey"
cat $A5 > $tmp_f
analyze
