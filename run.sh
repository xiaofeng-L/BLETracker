#!/bin/bash
pv="proverif-tamarin" 
# proverif-tamarin Apple_initialization.spthy
tmr="tamarin-prover"
# tamarin-prover /model/ --prove

f_Apple_Initial_C_P7_8_9="./model/Apple_initialization.spthy"
f_Apple_Initial_A_P11="./model/Apple_initialization_Authentication.spthy"
f_Apple_LocTrack_C_P10="./model/Apple_location.spthy"
f_Apple_LocTrack_A_P12_13="./model/P12_P13_Apple_broadcast.spthy"

f_Samsung_Initial_C_P4="./model/Samsung_initialization_Confidentiality.spthy"
f_Samsung_Initial_A_P3="./model/Samsung_initialization_Authentication.spthy"
f_Samsung_Initial_A_P3_fixV1="./model/Samsung_initialization_Authentication_fixed_V1.spthy"
f_Samsung_LocTrack_C_P1_E2E="./model/Samsung_location_E2E.spthy"
f_Samsung_LocTrack_C_P1_NoE2E="./model/Samsung_location_NoE2E.spthy"
f_Samsung_LocTrack_A_P2="./model/P2_Samsung_broadcast_ID.spthy"
f_Samsung_LocTrack_A_P5="./model/P5_Samsung_broadcast_AdvAddr.spthy"
f_Samsung_LocTrack_A_P6="./model/P6_Samsung_broadcast_pubkey.spthy"

prepare () {
	part="$1"
	property="$2"
	outdir="results-$title-$1-$2"
	mkdir -p $outdir
	tmp_f="$outdir/model.pv"
	out_f="$outdir/output.txt"
	option_pv_trans="-m=proverif"
	option_tmr_run="--prove"
}

analyze () {
	f_model="$1"
	result_pv=false

	echo "Using ProVerif"
	$tmr $1 "-m=proverif" > $tmp_f
	time $pv "-html $outdir" $tmp_f | tee $out_f | grep RESULT2

	grep "RESULT.*false" $out_f | while read -r line ; do
		# property=$(echo $line | awk -F '[([]' '{ print $2 }')
		if [[ $line == *"A trace has been found"* ]]; then
			result_pv=true
		fi
	done

	
	if result_pv=false ; then
		echo "Using TAMARIN"
		time $tmr $1 "--prove"
	fi
	# Some space before the next entry
	echo ""
}


echo "Verifying Apple initialization confidentiality."
prepare "apple_initial" "C_P7_8_9"
analyze $f_Apple_Initial_C_P7_8_9

echo "Verifying Apple initialization authentication."
prepare "apple_initial" "A_P11"
analyze $f_Apple_Initial_A_P11

echo "Verifying Apple location tracking confidentiality."
prepare "apple_LocTrack" "C_P10"
analyze $f_Apple_LocTrack_C_P10

echo "Verifying Apple location tracking anonymity."
prepare "apple_LocTrack" "A_P12_13"
analyze $f_Apple_LocTrack_A_P12_13


echo "Verifying Samsung initialization confidentiality."
prepare "apple_initial" "C_P4"
analyze $f_Samsung_Initial_C_P4

echo "Verifying Samsung initialization authentication."
prepare "apple_initial" "A_P3"
analyze $f_Samsung_Initial_A_P3

echo "Verifying Samsung initialization authentication after fixing V1."
prepare "apple_initial" "A_P3_fixV1"
analyze $f_Samsung_Initial_A_P3_fixV1

echo "Verifying Samsung location tracking confidentiality with E2E."
prepare "apple_LocTrack" "C_P1_E2E"
analyze $f_Samsung_LocTrack_C_P1_E2E

echo "Verifying Samsung location tracking confidentiality with NoE2E."
prepare "apple_LocTrack" "C_P1_NoE2E"
analyze $f_Samsung_LocTrack_C_P1_NoE2E

echo "Verifying Samsung location tracking anonymity."
prepare "apple_LocTrack" "A_P2"
analyze $f_Samsung_LocTrack_A_P2
echo "Verifying Samsung location tracking anonymity."
prepare "apple_LocTrack" "A_P5"
analyze $f_Samsung_LocTrack_A_P5
echo "Verifying Samsung location tracking anonymity."
prepare "apple_LocTrack" "A_P6"
analyze $f_Samsung_LocTrack_A_P6