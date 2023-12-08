# BLETracker_proverif
## File explanation

The **model** folder contains our models implemented in SAPIC+.

- **model/Apple_initialization.spthy** contains the model of Apple initialization protocol.
- **model/Apple_initialization_Authentication.spthy** contains the model of Apple initialization protocol for authentication.
- **model/P12_P13_Apple_broadcast.spthy** contains the model of the Apple location tracking protocol for anonymity.
- **model/Apple_location.spthy** contains the model of Apple location tracking protocol.


- **model/Samsung_initialization_Confidentiality.spthy** contains the model of the Samsung initialization protocol.
- **model/Samsung_initialization_Authentication.spthy** contains the model of the Samsung initialization protocol for authentication.
- **model/Samsung_initialization_Authentication_fixed_V1.spthy** contains the model of the Samsung broadcast protocol for authentication after fixing V1.
- **model/P2_Samsung_broadcast_ID.spthy** contains the model of the location tracking protocol for the anonymity of SmartTag's ID.
- **model/P5_Samsung_broadcast_AdvAddr.spthy** contains the model of the Samsung location tracking protocol for the anonymity of SmartTag's BLE MAC address.
- **model/P6_Samsung_broadcast_pubkey.pv** contains the model of the Samsung location tracking protocol for the anonymity of SmartTag's public key.
- **model/Samsung_location_E2E.spthy** contains the model of Samsung location tracking protocol (E2E).
- **model/Samsung_location_NoE2E.spthy** contains the model of Samsung location tracking protocol (NoE2E).


The ***.sh** scripts under the root folder contain the verification scripts of the corresponding protocol and the fixed protocol.
TODO:wy. Or describe the command and merge it into "How to run"

The **output** folder contains all the results generated by ProVerif when detecting the violations.

The **attack_traces** folder contains all the attack traces generated by ProVerif or Tamarin when detecting violations.
We identified three new vulnerabilities by a formal analysis and rediscovered three vulnerabilities found by reverse engineering.
- Rediscover V1, V3, V4
- Identify V5, V6, V7
TODO: lxf


## How to run

TODO:wy. How to run SAPIC+? For example, (1) build docker, following some documents of SAPIC+; (2) transfer model in SAPIC+ into Tamarin or ProVerif; (3) run.
