ryu-rfproxy
===========

A port of the RFProxy application to Ryu. This repository is referenced by a
core RouteFlow repository, and it is recommended to install via that
repository (see "Building" below).

Dependencies
-----------

* RouteFlow
* Ryu-2.0

Building
--------

Ryu-rfproxy requires RouteFlow to run. The usual way to install RouteFlow and
all of its dependencies is as follows:

1) Clone RouteFlow

```$ git clone git@github.com:routeflow/RouteFlow.git```

2) Fetch dependencies and install VMs (This will clone this repository)

```$ RouteFlow/build.sh -i ryu```

Running
-------

RouteFlow usually supplies a script to run all of the components in the
correct order. If you want to run ryu-rfproxy, load the app by using
ryu-manager in the RouteFlow directory:

```$ cd RouteFlow; ryu-manager ryu-rfproxy/rfproxy.py```

FAQ
---

Q. When I run RouteFlow, I get messages about the database connection failing:

```ovs-vsctl: unix:/usr/local/var/run/openvswitch/db.sock:
   database connection failed (No such file or directory)```

A. Check that ovsdb-server and ovs-vswitchd are up and running correctly. If
you're using a version of Open vSwitch compiled from source, you may need to
start them manually. Open vSwitch's
[INSTALL](http://git.openvswitch.org/cgi-bin/gitweb.cgi?p=openvswitch;a=blob_plain;f=INSTALL;hb=HEAD)
file has more information on this topic.

License
-------

This project uses the Apache License version 2.0. See LICENSE for more details.
