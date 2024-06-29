# BLETracker
## File explanation

### "_models" folder
The **_models** folder contains our models implemented in SAPIC+, which can be translated to the TAMARIN, ProVerif, and DeepSec models using SAPIC+.  
**.spthy** is the SAPIC+ models, **.spthy.dps** is the DeepSec models translated by SAPIC+.

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


### "_fixed_model" folder
The **_fixed_model** folder contains the models with our changes.

f_fixed_Samsung_LocTrack_P1_server_privacy="./_models_fixed/P1_fixed_MI1_3_Samsung_location_fixed_server_privacy.spthy"
f_fixed_Samsung_LocTrack_P2="./_models_fixed/P2_fixed_V3_Samsung_location_fixed_unlinkability.spthy.dps"
f_fixed_Samsung_Initial_P3="./_models_fixed/P3_fixed_V1_V5_Samsung_initialization_Authentication.spthy"
f_fixed_Samsung_Initial_P4="./_models_fixed/P4_fixed_V4_Samsung_initialization_confidentiality.spthy"
f_fixed_Apple_Initial_P5_6_7_8="./_models_fixed/P5_6_7_8_fixed_V6_Apple_simplified_initialization_confidentiality"
f_fixed_Apple_LocTrack_P9_server_privacy="./_models_fixed/P9_fixed_MI4_Apple_location_server_privacy.spthy"
f_fixed_Apple_Initial_P10="./_models_fixed/P10_fixed_V6_Apple_simplified_initialization_authentication.spthy"
f_fixed_Apple_LocTrack_P11="./_models_fixed/P11_fixed_Apple_location_unlinkability.spthy.dps"

### "result" folder
We log the verification results of all properties in the folder.

### "attack_trace" folder
We identified three new vulnerabilities by a formal analysis and rediscovered three vulnerabilities found by reverse engineering.
- Rediscover: V1(ProVerif), V3(ProVerif), V4(ProVerif), MI1(ProVerif) 
- Identify: V5(TAMARIN), V6(ProVerif), V7(ProVerif), MI3(ProVerif), MI4(Tamarin)

The **attack_trace** folder contains all the attack traces generated by TAMARIN and ProVerif when detecting the violations.
- The **.html** files contain the attack traces in the text generated by ProVerif.
- The **.pdf** files contain the attack traces in the graph generated by ProVerif.
- The **.txt** files contain the attack traces in the text generated by TAMARIN.
- The **.png** files contain the attack traces in the graph generated by TAMARIN with GUI.

### "RE" folder
We perform our reverse engineering on Samsung Find My Mobile using Galaxy S7 and Galaxy S9 smartphones and two SmartTags with firmware versions 01.01.26 and 01.02.06. The versions of the related Android applications are com.samsung.android.oneconnect: 1.7.73.22, com.samsung.android.plugin.fme: 1.7.73.332, and com.samsung.android.fmm: 7.2.21.0.

We take ethical issues seriously. In this study, we used our two Samsung devices and accounts for our experiments, and we took measures to minimize the impact on Samsung's services and only tested our own devices. Therefore, we provide the details of the Samsung Find My Mobile protocol and will not provide our attack scripts.

- The **RE/resources** folder contains the firmware of the SmartTag with version 01.01.26 and relevant applications.
- The **RE/results** folder contains part of our reverse engineering efforts.
  * The **RE/results/Samsung_initialization_traffic.zip** file contains the traffic while registering a SmartTag with version 01.02.06. But for anonymous submissions, we only reserve the related traffic.
  * The **RE/results/advertisement_compute.py** file contains the calculation of the advertisement generation process from the register results.
  * The **RE/results/hashed_sn.py** file contains the calculation of the value field "hashed_sn" via the MAC address of a SmartTag.
- The **RE/Review** folder is only available for reviewers and will not be released when published in the BLETracker repository.
  * The **RE/Review/PoC_BLEtraffic.zip** file contains a **RE/Review/attack_pair_bad_ECDH.py** file to decrypt the entire BLE traffic for the initialization phase, which is shown in **smartTagb_s7_white_01_02_06.pcapng**.
- The **Reverse Engineering for Samsung Find My Mobile.zip** contains the detailed process when we reverse-engineered Samsung Find My Mobile from shallow to deep.
## How to run
1. **Download the Image**

    First, Download the sapicplusplatform Docker image from the https://hub.docker.com/r/robertkuennemann/sapicplusplatform or using the command: 

    ```
       docker pull robertkuennemann/sapicplusplatform
    ```


2. **Build The Docker**

    Build the Docker Container using Terminal: 

    ```
       docker run -it robertkuennemann/sapicplusplatform:latest bash
    ```

    Then use the port mapping and disk mapping, you can use the -v and -p parameter, for example: 

    ```
       docker run -v /home/:/home/ -p 3001:3001-it robertkuennemann/sapicplusplatform:latest bash
    ```

3. **Execute**
   
    For short, you can run the "run.sh" to verify all properties.

4. **Others**
   
    To verify a certain property, you can follow directly execute the following command.
   
    Execute the scripts below for the export:
      -  `proverif-tamarin  ..` Translates input file with the modified tamarin-prover and runs proverif on output.
      -  `progsverif-tamarin  ..` same for gsverif
      -  `proverif-tamarin-diff ..` same for proverif with diff queries
      -  `deepsec-tamarin ..` same for deepsec
    
    The usage is `[proverif|progsverif|deepsec]-tamarin file`, for example, to verify the **Apple_initialization.spthy** using the **ProVerif**:
    
    ```
       proverif-tamarin Apple_initialization.spthy
    ```
    
    
    Or you can use the platform
    
    ```
        -m --output-module[=spthy|spthytyped|msr|proverif|deepsec]  What to output:- spthy (including
                                                                    processes),- spthy with explicit types,- pure
                                                                    msrs (processes translated to msrs) or- DeepSec
                                                                    or- ProVerif.
    ```
    
      other important tamarin-flags are:
    
      ```
          --prove[=LEMMAPREFIX*|LEMMANAME]                         Attempt to prove all lemmas that start with
                                                                  LEMMAPREFIX or the lemma which name is
                                                                  LEMMANAME
          -D --defines[=STRING]                                       Define flags for pseudo-preprocessor
          --diff                                                   Turn on observational equivalence mode using
                                                                  diff terms
      ```
    
    For example, you can use the ```tamarin-prover /model/Apple_initialization.spthy --prove``` to verify the **Apple_initialization.spthy** using the **tamarin-prover**.
    
    Or in this docker image, try the following command to verify the **Apple_initialization.spthy** using the **proverif** with additional parameters:
    
    ```
        tamarin-prover Apple_initialization.spthy -m=proverif > ex1.pv
        proverif ex1.pv -html ./result ex1.pv 
    ```
    
    
    You can also use the tamarin's interactive mode:
    
    - set up the following alias to give the image access to your host's current working
      dir (at the time of calling) and forward port 3001:
    
      ```alias pp='docker run -p 3001:3001 -v "$PWD:$PWD" -w "$PWD" robertkuennemann/sapicplusplatform'```
    
    - run, e.g., "pp tamarin-prover" to run tamarin-prover from the docker
    - remember to use the "-i" flag in tamarin's interactive mode to accept clients
      on all interfaces, as the docker host is not localhost to the guest:
    
    For example, please try ```tamarin-prover interactive -i='*4' /home/model/Apple_initialization.spthy``` to verify the **Apple_initialization.spthy** using the **tamarin-prover**'s interactive mode.
