#!/bin/bash
pv="/opt/protocolplatform/progsverif-tamarin" 
# proverif-tamarin Apple_initialization.spthy
tmr="tamarin-prover"
dc="deepsec"
# tamarin-prover /model/ --prove

f_Apple_Initial_C_P5_6_7_8="./_models/Apple/initialization/Apple_simplified_initialization_confidentiality_V6.spthy"
f_Apple_Initial_A_P10="./_models/Apple/initialization/Apple_simplified_initialization_authentication.spthy"
f_Apple_LocTrack_C_P9_confidentiality="./_models/Apple/location_tracking/Apple_location_confidentiality.spthy"
f_Apple_LocTrack_C_P9_server_privacy="./_models/Apple/location_tracking/Apple_location_server_privacy.spthy"
f_Apple_LocTrack_A_P11="./_models/Apple/location_tracking/Apple_location_unlinkability.spthy.dps"

f_Samsung_Initial_C_P4="./_models/Samsung/Samsung/initialization/Samsung_initialization_Confidentiality_foundV5.spthy"
f_Samsung_Initial_A_P3="./_models/Samsung/initialization/Samsung_initialization_Authentication_foundV1.spthy"
f_Samsung_Initial_A_P3_fixV1="./_models/Samsung/initialization/Samsung_initialization_Authentication_fixed_V1_foundV4.spthy"
f_Samsung_LocTrack_C_P1_E2E_confidentiality="./_models/Samsung/location_tracking/Samsung_location_E2E_confidentiality.spthy"
f_Samsung_LocTrack_C_P1_E2E_server_privacy="./_models/Samsung/location_tracking/Samsung_location_E2E_server_privacy.spthy"
f_Samsung_LocTrack_C_P1_NoE2E_confidentiality="./_models/Samsung/location_tracking/Samsung_location_NoE2E_confidentiality.spthy"
f_Samsung_LocTrack_C_P1_NoE2E_server_privacy="./_models/Samsung/location_tracking/Samsung_location_NoE2E_server_privacy.spthy"
f_Samsung_LocTrack_A_P2_E2E="./_models/Samsung/location_tracking/Samsung_location_E2E_unlinkability.spthy.dps"
f_Samsung_LocTrack_A_P2_NoE2E="./_models/Samsung/location_tracking/Samsung_location_NoE2E_unlinkability.spthy.dps"



f_fixed_Samsung_LocTrack_P1_server_privacy="./_models_fixed/P1_fixed_MI1_2_Samsung_location_fixed_server_privacy.spthy"
f_fixed_Samsung_LocTrack_P2="./_models_fixed/P2_fixed_V3_Samsung_location_fixed_unlinkability.spthy.dps"
f_fixed_Samsung_Initial_P3="./_models_fixed/P3_fixed_V1_V5_Samsung_initialization_Authentication.spthy"
f_fixed_Samsung_Initial_P4="./_models_fixed/P4_fixed_V4_Samsung_initialization_confidentiality.spthy"
f_fixed_Apple_Initial_P5_6_7_8="./_models_fixed/P5_6_7_8_fixed_V6_Apple_simplified_initialization_confidentiality"
f_fixed_Apple_LocTrack_P9_server_privacy="./_models_fixed/P9_fixed_MI3_Apple_location_server_privacy.spthy"
f_fixed_Apple_Initial_P10="./_models_fixed/P10_fixed_V6_Apple_simplified_initialization_authentication.spthy"
f_fixed_Apple_LocTrack_P11="./_models_fixed/P11_fixed_Apple_location_unlinkability.spthy.dps"



prepare () {
  outdir="results"
  fix_ourdir="results_fixed"
  mkdir -p $outdir
}


analyze_pv () {
  f_model="$1"
  part="_proverif_"
  property="$2"
  vendor="$3"
  f_log="$outdir/$vnedor_$property$part.log"

  echo "Using ProVerif"
  time $pv $1 > $f_log &

  echo ""
}
analyze_tmr () {
  f_model="$1"
  part="_tamarin_"
  property="$2"
  vendor="$3"
  f_log="$outdir/$vnedor_$property$part.log"

  echo "Using Tamarin"
  time $tmr $1 --prove > $f_log &

  echo ""
}
analyze_tmr_auth () {
  f_model="$1"
  part="_tamarin_"
  property="$2"
  vendor="$3"
  f_log="$outdir/$vnedor_$property$part.log"

  echo "Using Tamarin"
  time $tmr $1 --prove=pair* > $f_log &

  echo ""
}
analyze_tmr_conf () {
  f_model="$1"
  part="_tamarin_"
  property="$2"
  vendor="$3"
  f_log="$outdir/$vnedor_$property$part.log"

  echo "Using Tamarin"
  time $tmr $1 --prove=confidentiality* > $f_log &

  echo ""
}

analyze_tmr_heuristic () {
  f_model="$1"
  part="_tamarin_"
  property="$2"
  vendor="$3"
  f_log="$outdir/$vnedor_$property$part.log"

  echo "Using Tamarin"
  time $tmr $1 --prove --heuristic > $f_log &

  echo ""
}
analyze_tmr_heuristic_auth () {
  f_model="$1"
  part="_tamarin_"
  property="$2"
  vendor="$3"
  f_log="$outdir/$vnedor_$property$part.log"

  echo "Using Tamarin"
  time $tmr $1 --prove=pair* --heuristic > $f_log &

  echo ""
}
analyze_tmr_heuristic_conf () {
  f_model="$1"
  part="_tamarin_"
  property="$2"
  vendor="$3"
  f_log="$outdir/$vnedor_$property$part.log"

  echo "Using Tamarin"
  time $tmr $1 --prove=confidentiality* --heuristic > $f_log &

  echo ""
}
analyze_dc () {
  f_model="$1"
  part="_deepsec_"
  property="$2"
  vendor="$3"
  f_log="$outdir/$vnedor_$property$part.log"

  echo "Using DeepSec"
  time $dc $1 --trace > $f_log &

  echo ""
}

prepare

echo "P1: Confidentiality of location: Samsung location tracking with E2E."
analyze_pv $f_Samsung_LocTrack_C_P1_E2E_confidentiality "P1_E2E_confidentiality" "Samsung"
analyze_tmr $f_Samsung_LocTrack_C_P1_E2E_confidentiality "P1_E2E_confidentiality" "Samsung"
analyze_pv $f_Samsung_LocTrack_C_P1_E2E_server_privacy "P1_E2E_server_privacy" "Samsung"

echo "P1: Confidentiality of location: Samsung location tracking with NoE2E."
analyze_pv $f_Samsung_LocTrack_C_P1_NoE2E_confidentiality "P1_NoE2E_confidentiality" "Samsung"
analyze_tmr $f_Samsung_LocTrack_C_P1_NoE2E_confidentiality "P1_NoE2E_confidentiality" "Samsung"
analyze_pv $f_Samsung_LocTrack_C_P1_NoE2E_server_privacy "P1_NoE2E_server_privacy" "Samsung"




echo "P2: Unlinkability: Samsung location tracking with E2E."
analyze_dc $f_Samsung_LocTrack_A_P2_E2E "P2_E2E" "Samsung"

echo "P2: Unlinkability: Samsung location tracking with NoE2E."
analyze_dc $f_Samsung_LocTrack_A_P2_NoE2E "P2_NoE2E" "Samsung"




echo "P3: Authentication of tracker: Samsung initialization."
analyze_pv $f_Samsung_Initial_A_P3 "P3" "Samsung"

echo "P3+: Authentication of tracker: Samsung initialization after fixing V1."
analyze_pv $f_Samsung_Initial_A_P3_fixV1 "P3_fixV1" "Samsung"
analyze_tmr_auth $f_Samsung_Initial_A_P3_fixV1 "P3_fixV1" "Samsung"




echo "P4: Confidentiality of ID: Samsung initialization."
analyze_pv $f_Samsung_Initial_C_P4 "P4" "Samsung"




echo "P5/6/7/8: Confidentiality of master private key, master public key, symmetric key, and shared secret: Apple initialization."
analyze_pv $f_Apple_Initial_C_P5_6_7_8 "P5_6_7_8" "Apple"
analyze_tmr_heuristic_conf $f_Apple_Initial_C_P5_6_7_8 "P5_6_7_8" "Apple"



echo "P9: Confidentiality of location: Apple location tracking."
analyze_tmr $f_Apple_LocTrack_C_P9_confidentiality "P9_confidentiality" "Apple"
analyze_tmr $f_Apple_LocTrack_C_P9_server_privacy "P9_server_privacy" "Apple"



echo "P10: Authentication of tracker: Apple initialization."
analyze_pv $f_Apple_Initial_A_P10 "P10" "Apple"
analyze_tmr_heuristic $f_Apple_Initial_A_P10 "P10" "Apple"



echo "P11: Unlinkability: Apple location tracking."
analyze_dc $f_Apple_LocTrack_A_P11 "P11" "Apple"





echo "Verifying the fixed models"

echo "P1: Confidentiality of location: Samsung location tracking."
analyze_tmr $f_fixed_Samsung_LocTrack_P1_server_privacy "fixed_P1" "Samsung"

echo "P2: Unlinkability: Samsung location tracking with E2E."
analyze_dc $f_fixed_Samsung_LocTrack_P2 "fixed_P2" "Samsung"

echo "P3: Authentication of tracker: Samsung initialization."
analyze_tmr_auth $f_fixed_Samsung_Initial_P3 "fixed_P3" "Samsung"

echo "P4: Confidentiality of ID: Samsung initialization."
analyze_pv $f_fixed_Samsung_Initial_P4 "fixed_P4" "Samsung"



echo "P5/6/7/8: Confidentiality of master private key, master public key, symmetric key, and shared secret: Apple initialization."
analyze_tmr_heuristic_conf $f_fixed_Apple_Initial_P5_6_7_8 "fixed_P5_6_7_8" "Apple"

echo "P9: Confidentiality of location: Apple location tracking."
analyze_tmr $f_fixed_Apple_LocTrack_P9_server_privacy "fixed_P9" "Apple"

echo "P10: Authentication of tracker: Apple initialization."
analyze_tmr_heuristic_auth $f_fixed_Apple_Initial_P10 "fixed_P10" "Apple"

echo "P11: Unlinkability: Apple location tracking."
analyze_dc $f_fixed_Apple_LocTrack_P11 "fixed_P11" "Apple"