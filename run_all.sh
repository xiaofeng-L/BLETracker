#!/bin/bash

echo "Verify all protocols and the fixed protocols. It may take up to a few minutes to finish."
sleep 3

bash ./verify_a_l.sh

bash ./verify_a_p.sh

bash ./verify_s_l.sh

bash ./verify_s_p.sh
