# zeek_halfduplex_analyzer
Analyzes a Zeek/Bro conn.log script and outputs stats about half-duplex connections.  Can be used to troubleshoot problems with asymmetric hashing and asymmetric flows

## Background
This script extends the functionality from the check_SAD_connections option in [bro-doctor](https://github.com/ncsa/bro-doctor/blob/master/doctor.py).  Currently only ascii (non-json) logs are supported.

It reads an entire conn.log file and only keeps lines that
* Are tcp
* Have both a local_orig and local_resp
* Have multi-character history fields

It determines which lines are half-duplex based on an entirely uppercase or entirely lowercase history field, then outputs what percentage of the 
total connections, TCP connections, and analyzed connections are half-duplex.

It also outputs top ten half-duplex history types and IP address pairs, by count and by percentage, and additionally outputs tables of where
the half-duplex connections occurred, by NIC and by Zeek/Bro process name.

Based on originator/responder IP address and port, it also tries to determine which half-duplex connections had both sides of the conversation seen 
(e.g. an asymmetric hashing issue occurred), and outputs some stats about those.

## Running

Location of the conn.log should be given as an argument on the command line:

```
./zeek_halfduplex_analyzer.py /srv/zeek/logs/current/conn.log
```
