# IP support programs

This directory contains two support programs for IP:

 - ref_node: This is the reference version of the IP node you will be
   building.  Your node should be able to interoperate with this one.

 - net2lnx: Utility for converting .net files (which describe a
   virtual network) into .lnx files (input to run each node).  The
   source code for this program has been provided, but you should not
   need to view or change it.  Rather, if the compiled version of the
   program provided doesn't work on your platform, you can rebuild it
   with `make`.  
