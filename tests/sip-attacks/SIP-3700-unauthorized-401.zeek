# @TEST-EXEC: zeek -C -r $TRACES/SIP-3700-unauthorized-401.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

