
module SIP; 

export 
{

	global sip_scanners: table[addr] of count &redef &read_expire=1 hrs &default=0 ; 
	
	redef enum Notice::Type += {
                SIP_403_Forbidden, 
                SIP_401_Unauthorized, 
		Code_401_403, 
		SipviciousScan, 
		BadUserAgent, 
                };


	global malicious_sip: pattern =  /VaxSIPUserAgent|sipvicious|[Ss][Ii][Pp][Vv][Ii][Cc][Ii][Oo][Uu][Ss]|friendly-scanner|nm@nm|nm2@nm2|[Nn][Mm][0-9]@[Nn][Mm][0-9]/ &redef ; 

	global sip_block_codes: set[count] = { 403, 401 } ; 
	global sip_block_reason: pattern = /Forbidden|Unauthorized/ ; 

	global SIP::m_w_add_sip_scanner: event(ip: addr);
	global SIP::w_m_new_sip_scanner: event(cid: conn_id);
	global SIP::w_m_BadUserAgent: event(cid: conn_id);

	global sip_BadUserAgent: function(cid: conn_id ); 

	global sip_401_403: function(cid:conn_id); 


	
}

#@if ( Cluster::is_enabled() )
#@load base/frameworks/cluster
#redef Cluster::manager2worker_events += /SIP::m_w_add_sip_scanner/; 
#redef Cluster::worker2manager_events += /SIP::w_m_new_sip_scanner|SIP::w_m_BadUserAgent/ ; 
#@endif

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event zeek_init()
        {
        Broker::auto_publish(Cluster::worker_topic, SIP::m_w_add_sip_scanner) ; 
        }
@else
event zeek_init()
        {
        Broker::auto_publish(Cluster::manager_topic, SIP::w_m_new_sip_scanner) ; 
        Broker::auto_publish(Cluster::manager_topic, SIP::w_m_BadUserAgent) ; 
        }
@endif

@endif




@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
event SIP::w_m_new_sip_scanner(cid: conn_id)
{
	sip_401_403(cid); 
	event SIP::m_w_add_sip_scanner(cid$orig_h);

} 
@endif 



@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )
event SIP::m_w_add_sip_scanner(ip: addr)
{ 
	if (ip !in sip_scanners)
		sip_scanners[ip] += 5 ; 
} 
@endif 


function sip_401_403 (cid: conn_id)
{

	print fmt ("here here"); 

	local src = cid$orig_h ; 

	if (src !in sip_scanners)
       		sip_scanners[src] += 0  ;

	sip_scanners[src] += 1  ;

       if (sip_scanners[src] >= 5)
       {
		NOTICE([$note=SIP::Code_401_403,
               		$id=cid,
                       	$suppress_for=6hrs,
			$msg=fmt("SIP bruteforce: 401-403 Forbidden"),
                       	$identifier=cat(cid$orig_h)]);
        }
} 




event sip_reply (c: connection , version: string , code: count , reason: string )
{ 
	#print fmt ("%s", sip_scanners) ; 
	#print fmt ("sip_reply: version: %s, code: %s, reason : %s", version, code, reason ); 

	local src=c$id$orig_h ; 

	if (src in sip_scanners && |sip_scanners[src]| > 5 )
		return ; 
	
	if (code in sip_block_codes && sip_block_reason in reason ) 
	{ 
	@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
                event SIP::w_m_new_sip_scanner(c$id);
        @else
                sip_401_403(c$id);
        @endif
	} 

} 


function sip_BadUserAgent(cid: conn_id ) 
{ 
	NOTICE([$note=SIP::BadUserAgent, $id=cid,
               	$suppress_for=6hrs, $msg=fmt("Sipvicious Scan seen"),
               	$identifier=cat(cid$orig_h)]);
}



@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event SIP::w_m_BadUserAgent(cid: conn_id)
{
        sip_BadUserAgent(cid);
	event SIP::m_w_add_sip_scanner(cid$orig_h);


}
@endif

event sip_header (c: connection, is_orig: bool, name: string, value: string)
{ 
	#print fmt ("sip_header: name :%s, value: %s", name, value); 

	#if ((name == "FROM"||name == "TO"||name == "USER-AGENT") && malicious_sip in value))
	if (name == "FROM" && malicious_sip in value)
        {
	@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )) 
		event SIP::w_m_BadUserAgent(c$id);
	@else
		sip_BadUserAgent(c$id);
	@endif	 

	} 

} 


#sip_request: method: OPTIONS, URI: sip:100@128.3.0.0, version: 2.0
#sip_header: name :VIA, value: SIP/2.0/UDP 149.3.142.10:5251;branch=z9hG4bK-1477480868;rport
#sip_header: name :CONTENT-LENGTH, value: 0
#sip_header: name :FROM, value: "sipvicious"<sip:100@1.1.1.1>;tag=3830303330303030313761630131333132303130313639
#sip_header: name :ACCEPT, value: application/sdp
#sip_header: name :USER-AGENT, value: friendly-scanner
#sip_header: name :TO, value: "sipvicious"<sip:100@1.1.1.1>
#sip_header: name :CONTACT, value: sip:100@149.3.142.10:5251
#sip_header: name :CSEQ, value: 1 OPTIONS
#sip_header: name :CALL-ID, value: 649920334966295388970831
#sip_header: name :MAX-FORWARDS, value: 70
