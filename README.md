# Handshaker
Performs custom TCP handshakes

This python script creates custom tcp handshakes it allows you to customize everything.
You can set the Evil bit or the Tcp reserved bits for Ctfs if you need to.

Requirements:

Create an Iptable rule to prevent RST packets to be automatically sent
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
installing the python librarys using pip3 

example use
sudo python3 ./Handshaker.py -dIP 10.10.10.1 -dPort 4242 -sIP 10.10.10.2 -sPort 1505
-dIP destinationIP -dPort destinationPort -sIP sourceIP -sPort sourcePort

You can add custom TCP payloads in the script yourself.

