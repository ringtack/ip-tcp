# CS168 RIP Dissector

This directory contains a dissector (also known as a decoder) for the
RIP protocol implementation for CS168.  

## Installation Instructions

The dissector is provided as a Lua script in this directory.  For
security reasons, Wireshark does not run Lua scripts when run as
root--therefore, you must ensure that you are using Wireshark as your
local user, not with root or sudo.  To run wireshark as a standard
user, make sure your user is added to the `wireshark` group.  If you
are using the provided VM, the the vagrant user is already in the
wireshark group.  However, if you are running Wireshark on your own
system, you will need to configure this yourself.  

Once you have Wireshark running as your user.  Add the dissector to
Wireshark, by copying the script into your plugins directory.

To do this:
 0. Run wireshark as your user (**not with root or sudo**).  
 1. Open Wireshark's Help menu and select "About Wireshark".  
 2. In the folders tab, find the entry "Personal Lua Plugins".  For
    example:  `~/.config/wireshark/plugins`
 3. Copy the script to this directory (if it doesn't exist, create it)
    and restart wireshark
 4. Open the "About Wireshark" window again and look in the Plugins
    tab.  You should now see cs168_rip.lua in the list of plugins.  
	
## Using the dissector

Note:  To make sure your dissector is working, please run the reference IP
node with an example network to ensure you are testing with correct
packets.

Wireshark will automatically invoke the RIP dissector when it
encounters an IP packet using protocol number 200.  

Four our overlay network, however, Wireshark does not automatically
know to interpret our IP-in-UDP packets as IP packets.  You can tell
wireshark to do this using its "User-specified decodes" feature:
  1. Start capturing traffic for the IP assignment.  In most cases,
     you will be capturing on the loopback interface.  
  2. Find a UDP packet related to the assignment and select it.  These
     packets will use the port numbers specified in the lnx files, and
     therefore may be different depending on the network you are running.  
  3. Look in the lower pane that shows the layers present in ths
     packet.  Under UDP, you should see a layer "Data" that contains
     our Virtual IP packets.  Select this field.
  4. Right-click on the field and select "**Decode As...**"  This should
     open a window and add a rule template to decode UDP traffic on the port
     number used in the packet.  In the rightmost column ("Current"),
     select the IPv4 decoder, then click "**Save**".
  5. Wireshark should now update and decode the UDP packets first as
     IP packets, and then decode those with protocol 200 as RIP using
     the dissector you installed.

If you do not see IP packets encapsulated in your UDP packets, check
your "Decode as... rules from Step 5.  If you do not see RIP being
decoded, make sure the plugin is loaded in the help menu.  

**Note**: this will only invoke the correct decoder on a single UDP
port.  If you want to decode the traffic for multiple nodes, repeat
this process for each port you need to observe.

## Feedback

This decoder and the instructions are new.  If you have questions or
encounter any issues, please post on Piazza or see the course staff
for help.
