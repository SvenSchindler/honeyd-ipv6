# About

This project is an extension of Honeyd 1.5c with a custom IPv6 network stack and improved support for high-interaction honeypots. Honeyd was initially developed by
Niels Provos and can be downloaded [here](http://www.honeyd.org). You can find the original README file [here](./README-15c). This IPv6 version is
one result some IPv6 research activity that I conducted until recently. Even though I tested all major features in a long term experiment, it's probably not as evolved as a commercial product. So keep an eye on it when you're using it to catch attackers in IPv6 networks ;).

# Implemented IPv6 features

* ICMPv6 echo requests/replies

* essential parts of the Neighbor Discovery Protocol

* run TCP and UDP scripts via IPv6

* IPv6 fragmentation

* IPv6 packet routing simulation including network latency and packet drops

* random mode to dynamically create virtual IPv6 machines on demand

# Compile and Install

Download the Honeyd IPv6 sources from the files section. This version requires the same libraries
as the original Honeyd Version 1.5c. Please refer to [http://www.honeyd.org](http://www.honeyd.org) for more information.
Make sure to compile Honeyd for IPv6 against *libevent 1.4.x, version 2.x will not work*!
When you're finished installing the required dependencies, run the following commands:

```
./configure
make && make install
```

# Configuration

I adapted the basic configuration statements to support IPv6 addresses. A short example configuration can be
found in the source archive. Please refer to [http://www.honeyd.org](http://www.honeyd.org) for configuration details.
Known Issues and missing Features

* The tool needs to be run behind a router that sends router advertisements in order to determine the ethernet address of the next hop. You can use the router_add.py script to send a fake router advertisement if you don't have a router with advertisements enabled running.

* Tunneling is not yet supported.


# Acknowledgments

I would like to say thank you to the following people who provided ideas, advices and code to turn honeyd into an IPv6-capable honeypot: 

Niels Provos
Sebastian Menski
Oliver Eggert
Prof. Dr. Thomas Scheffler
Prof. Dr. Bettina Schnor