# BLETracker
## File explanation

### "model" folder
The **model** folder contains our models implemented in SAPIC+, which can be translated to the TAMARIN models and ProVerif models using SAPIC+.  

- **model/Apple_initialization.spthy** contains the model of Apple initialization protocol.
- **model/Apple_initialization_Authentication.spthy** contains the model of Apple initialization protocol for authentication.
- **model/P12_P13_Apple_broadcast.spthy** contains the model of the Apple location tracking protocol for anonymity.
- **model/Apple_location.spthy** contains the model of Apple location tracking protocol.


- **model/Samsung_initialization_Confidentiality.spthy** contains the model of the Samsung initialization protocol.
- **model/Samsung_initialization_Authentication.spthy** contains the model of the Samsung initialization protocol for authentication.
- **model/Samsung_initialization_Authentication_fixed_V1.spthy** contains the model of the Samsung broadcast protocol for authentication after fixing V1.
- **model/P2_Samsung_broadcast_ID.spthy** contains the model of the location tracking protocol for the anonymity of SmartTag's ID.
- **model/P5_Samsung_broadcast_AdvAddr.spthy** contains the model of the Samsung location tracking protocol for the anonymity of SmartTag's BLE MAC address.
- **model/P6_Samsung_broadcast_pubkey.spthy** contains the model of the Samsung location tracking protocol for the anonymity of SmartTag's public key.
- **model/Samsung_location_E2E.spthy** contains the model of Samsung location tracking protocol with the end-to-end mode (E2E).
- **model/Samsung_location_NoE2E.spthy** contains the model of Samsung location tracking protocol without the end-to-end mode (NoE2E).


### "fixed_model" folder
The **fixed_model** folder contains the models with our changes.

- **fixed_model/Apple_initialization_Confidentiality.spthy** contains the fixed model of the Apple initialization protocol.

- **fixed_model/Samsung_initialization_Confidentiality.spthy** contains the fixed model of the Samsung initialization protocol with all relevant changes for confidentiality.
- **fixed_model/Samsung_initialization_Authentication.spthy** contains the fixed model of the Samsung initialization protocol with all relevant changes for authentication.
- **fixed_model/Samsung_location_E2E.spthy** contains the fixed model of the Samsung location tracking protocol for confidentiality.
- **fixed_model/P6_Samsung_broadcast_pubkey.spthy** contains the fixed model of the Samsung location tracking protocol for the anonymity of SmartTag's public key.


### "result" folder
We identified three new vulnerabilities by a formal analysis and rediscovered three vulnerabilities found by reverse engineering.
- Rediscover: V1(ProVerif), V3(ProVerif), V4(ProVerif)
- Identify: V5(TAMARIN), V6(ProVerif), V7(ProVerif)

The **result** folder contains all the attack traces generated by TAMARIN and ProVerif when detecting the violations.
- The **.html** files contain the attack traces in the text generated by ProVerif.
- The **.pdf** files contain the attack traces in the graph generated by ProVerif.
- The **.txt** files contain the attack traces in the text generated by TAMARIN.
- The **.png** files contain the attack traces in the graph generated by TAMARIN with GUI.

### "RE" folder
We perform our reverse engineering on Samsung Find My Mobile using Galaxy S7 and Galaxy S9 smartphones and two SmartTags with firmware versions 01.01.26 and 01.02.06. The versions of the related Android applications are com.samsung.android.oneconnect: 1.7.73.22, com.samsung.android.plugin.fme: 1.7.73.332, and com.samsung.android.fmm: 7.2.21.0.

We take ethical issues seriously. In this study, we used our two Samsung devices and accounts for our experiments, and we took measures to minimize the impact on Samsung's services and only tested our own devices. Therefore, we provide the details of the Samsung Find My Mobile protocol and will not provide our attack scripts.

- The **resources** folder contains the firmware of the SmartTag with version 01.01.26 and relevant applications.
- The **results** folder contains part of our reverse engineering efforts.
  * The **results/Samsung_initialization_traffic.zip** file contains the traffic while registering a SmartTag with version 01.02.06.
  * The **results/advertisement_compute.py** file contains the calculation of the advertisement generation process from the register results.
  * The **results/hashed_sn.py** file contains the calculation of the value field "hashed_sn" via the MAC address of a SmartTag. 

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
