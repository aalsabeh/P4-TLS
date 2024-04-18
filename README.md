# P4-TLS
This project parses TLS SNI extension using P4 language on Tofino architecture. This repository contains:

    - P4/: P4 code that runs on Tofino. The program compiles on BF SDE 9.6.0.  
        - Set environment and compile:  
            - ~/bf-sde-9.6.0# . ../tools/set_sde.bash  
            - ~/bf-sde-9.6.0# ../tools/p4_build.sh --with-p4c=bf-p4c P4/basic.p4  
        - Run on Tofino Model:  
            # Note: the options "-f ports.json" is optional and custom to the topology that you have  
            - ~/bf-sde-9.6.0# ./run_tofino_model.sh -f ports.json -p basic  
            # Open a new terminal  
            - ~/bf-sde-9.6.0# . ../tools/set_sde.bash  
            - ~/bf-sde-9.6.0# ./run_switchd.sh -p basic  

    - CP/: Control plane programs. These programs contain python scripts that interact with the P4 data plane via bfrt_python. You will also find scripts that install rules in the data plane. For example, a rule that matches on the hostname "facebook.com".  
        # Install rules in the data plane to forward traffic based on IPv4 address.  
        - ~/bf-sde-9.6.0# . ../tools/set_sde.bash  
        - ~/bf-sde-9.6.0# ../run_bfshell.sh --no-status-srv -b CP/setup.py  
        # If you want to match on a hostname, such as 'facebook.com' using the fine-grained monitoring, which requires a match on the CRC32C hash value of 'facebook.com', you need to utilize the program CP.py. The function "calc_crc_32_servername" takes a servername as argument and returns its CRC32C hash. You need python3 with some libraries that can be easily installed via pip3 (crccheck, numpy, bitarray)  
        - python3 CP.py  
        # To send a TLS packet from host 1 to host h2 (dst = 10.0.0.2), you can use the custom script "Sender/send_tls_tofino2.py". The script send a TLS Client Hello packet with the hostname "facebook.com". The data plane has a rule for "facebook.com", and it will send it through port=3 (drop).
        - sender# sudo python3 Sender/send_tls_tofino2.py 10.0.0.2  
        
    - Datasets: scripts and links to the datasets used in the evaluations. 
