#!/bin/bash

# Tested with ProVerif version 2.04
pv=proverif

title="al"
sp_f="./model/Apple_location.pv"


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
# query attacker(location).
analyze () {
	time $pv $options $tmp_f | tee $out_f | grep RESULT

	grep "RESULT.*false" $out_f | while read -r line ; do
		# property=$(echo $line | awk -F '[([]' '{ print $2 }')
		if [[ $line == *"attacker(location[])"* ]]; then
			property="C1"
		fi
	done

	# Some space before the next entry
	echo ""
}


echo "Verifying Apple location confidentiality."
prepare "1" "al"
cat $sp_f > $tmp_f
echo "(step0o()) | (step1f()) | (step1s()) | (step2o()) | (step2s())" >> $tmp_f
analyze
