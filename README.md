ryu-rfproxy
===========

A port of the RFProxy application to Ryu. This repository is referenced by a
core RouteFlow repository, and it is recommended to install via that
repository (see "Building" below).

Dependencies
-----------

* RouteFlow
* Ryu

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

License
-------

This project uses the Apache License version 2.0. See LICENSE for more details.
