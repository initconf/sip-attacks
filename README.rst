=================================================================================
Simple policy to detect SIPG-3700: Reason SIP Gateway registration or authentication failed.
=================================================================================

Following functionality are provided by the script
--------------------------------------------------
::

        1) It identifies SIPG-3700 failures in SIP protocol 
        2) Generates a SIP::SIPG3700 alert/notice 

Installation
------------
	zeek-pkg install initconf/sip-attacks
	or
	@load sip-attacks/scripts 


Detailed Notes:
---------------

Detail Alerts and descriptions: Following alerts are generated by the script:
******************************************************************************

Heuristics  are simple: check for 

This should generate following Kinds of notices:

- SIP::BadUserAgent
- SIP::Code_401_403

Example Alert: 
***************************
::

1) 1515989011.284952	-	37.8.44.2	14622	131.243.4.100	5060	-	-	-	udp	SIP::Code_401_403	SIP bruteforce: 401-403 Forbidden	-	37.8.44.2	131.243.4.100	5060	-	-	Notice::ACTION_LOG,Notice::ACTION_DROP	3600.000000	-	-	-	-	-	F

2) 1565939098.345912	-	80.82.77.20	5274	131.243.0.1	5060	-	-	-	udp	SIP::BadUserAgent	Sipvicious Scan seen	-	80.82.77.20	131.243.0.1	5060	-	-	Notice::ACTION_LOG,Notice::ACTION_DROP	3600.000000	-	-	-	-	-	F

