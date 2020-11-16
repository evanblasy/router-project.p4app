# L3 Switch/ PWOSPF Router

This switch can forward ARP, IP, and PWOSPF packets. It learns the topology through PWOSPF Hello and LSU packets. Then it installs rules based on these packets. 

## Running

First, make sure you have p4app (which requires Docker):

    cd ~/
    git clone --branch rc-2.0.0 https://github.com/p4lang/p4app.git

Then run this p4app:

    ~/p4app/p4app run router-project.p4app
