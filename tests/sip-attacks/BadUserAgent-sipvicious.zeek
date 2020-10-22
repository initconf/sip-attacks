# @TEST-EXEC: zeek -C -r $TRACES/BadUserAgent-sipvicious.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

