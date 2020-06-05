CAIDA is a Automatic diagnostics troubleshooting assistant for ASA and FTD crypto ikev2 debugs.

This tool is optimized for debugging at verbosity level 250. To collect debug from the box please follow these steps:

1. From CLI run:
	Debug crypto condition peer x.x.x.x 
	Debug crypto ikev2 platform 250
	Debug crypto ikev2 protocol 250
	
	Note: Replace x.x.x.x with your peer address. To stop the debugs use "un all"
	
	Caution: On the ASA, you can set various debug levels; by default, level 1 is used.
	If you change the debug level, the verbosity of the debugs might increase. Do this with caution,
	especially in production environments! Note that the highest level of debugging is 255.
	
2.) Save your outputs in a file

3.) Click "Load File" and CAIDA will diagnose and troublshoot automatically.

CAIDA is a support tool for Network Admins & Engineers.
If your network is live, make sure that you understand the potential impact of any command.