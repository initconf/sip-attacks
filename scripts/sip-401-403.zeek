
module SIP; 

export 
{

	global sip_scanners: table[addr] of count &redef &write_expire=30 mins &default=0 ; 
	
	redef enum Notice::Type += {
                SIP_403_Forbidden, 
                SIP_401_Unauthorized, 
		Code_401_403, 
                };


	global sip_block_codes: set[count] = { 403, 401, 487, 503 } ; 
	global sip_block_reason: pattern = /Forbidden|Unauthorized|Request Terminated|Temporarily Unavailable/ ; 

	global SIP::m_w_add_sip_scanner: event(ip: addr);
	global SIP::w_m_new_sip_scanner: event(cid: conn_id);
	global sip_401_403: function(cid:conn_id); 

	global SIP_401_403_threshold = 10 ; 

}

function log_reporter(msg: string, debug: count)
{



	if (debug == 0) 
	{ 
	
	if (! Cluster::is_enabled() )
		print fmt ("%s", msg); 
	event reporter_info(current_time(), msg, peer_description);
	} 
}

#@if ( Cluster::is_enabled() )
#@load base/frameworks/cluster
#redef Cluster::manager2worker_events += /SIP::m_w_add_sip_scanner/; 
#redef Cluster::worker2manager_events += /SIP::w_m_new_sip_scanner/ ; 
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
        }
@endif

@endif



### runs on workers to update the sip_scanners table
### so that we don't have to process already flagged scanners

@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )|| ! Cluster::is_enabled() )
event SIP::m_w_add_sip_scanner(ip: addr)
{ 
	log_reporter(fmt("m_w_add_sip_scanner: %s", ip),0); 

	if (ip !in sip_scanners)
		sip_scanners[ip] += SIP_401_403_threshold ; 
} 
@endif 


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )
event SIP::w_m_new_sip_scanner(cid: conn_id)
{
	log_reporter(fmt("w_m_new_sip_scanner: %s", cid),0); 
	sip_401_403(cid); 
} 
@endif 

function sip_401_403 (cid: conn_id)
{

	log_reporter(fmt("function: sip_401_403: %s", cid),0); 
	local src = cid$orig_h ; 

	# to avoid actions on spoofing  (for now) - since zeek reverses
	# directionality - 
	
	if (src in Site::local_nets)
		return ; 


	if (src in sip_scanners && |sip_scanners[src]| >=SIP_401_403_threshold)
		return ; 

	if (src !in sip_scanners)
       		sip_scanners[src] += 0  ;

	sip_scanners[src] += 1  ;

       if (sip_scanners[src] >= SIP_401_403_threshold)
       {
		NOTICE([$note=SIP::Code_401_403,
               		$id=cid,
			$msg=fmt("SIP bruteforce: 401-403 Forbidden")]);
                       	#$suppress_for=6hrs,
                       	#$identifier=cat(cid$orig_h)]);

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
	event SIP::m_w_add_sip_scanner(cid$orig_h);
@endif 
        }

} 

event sip_reply (c: connection , version: string , code: count , reason: string )
{ 

	#print fmt ("%s", sip_scanners) ; 
	#print fmt ("sip_reply: version: %s, code: %s, reason : %s", version, code, reason ); 

	local src=c$id$orig_h ; 

	#if (src in sip_scanners)
	if (src in sip_scanners && |sip_scanners[src]| > SIP_401_403_threshold )
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
