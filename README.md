# P4-TLS
This project parses TLS SNI extension using P4 language on Tofino architecture. This repository contains:

    - P4/: P4 code that runs on Tofino. The program compiles on BF SDE 9.6.0.
    
    - CP/: Control plane programs. These programs contain python scripts that interact with the P4 data plane via bfrt_python. You will also find scripts that install rules in the data plane. For example, a rule that matches on the hostname "google.com".
    
    - Datasets: scripts and links to the datasets used in the evaluations. 
