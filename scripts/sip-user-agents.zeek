
module SIP; 

export 
{
	
	redef enum Notice::Type += {
		SipviciousScan, 
		BadUserAgent, 
                };

	global malicious_sip: pattern =  /VaxSIPUserAgent|sipvicious|[Ss][Ii][Pp][Vv][Ii][Cc][Ii][Oo][Uu][Ss]|friendly-scanner|nm@nm|nm2@nm2|[Nn][Mm][0-9]@[Nn][Mm][0-9]/ &redef ; 

	global SIP::w_m_BadUserAgent: event(cid: conn_id);
	global sip_BadUserAgent: function(cid: conn_id ); 
	
}

#@if ( Cluster::is_enabled() )

#@load base/frameworks/cluster
#redef Cluster::worker2manager_events += /SIP::w_m_BadUserAgent/ ; 
#@endif

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() == Cluster::WORKER )
event zeek_init()
        {
        Broker::auto_publish(Cluster::manager_topic, SIP::w_m_BadUserAgent) ; 
        }
@endif

@endif

event sip_header (c: connection, is_orig: bool, name: string, value: string)
{ 
	#print fmt ("sip_header: name :%s, value: %s", name, value); 

	local src = c$id$orig_h ; 

	# to avoid actions on spoofing  (for now) - since zeek reverses
        # directionality -

        if (src in Site::local_nets)
                return ;

	if (src in sip_scanners) 
		return ; 

	if ((name == "FROM"||name == "TO"||name == "USER-AGENT") && malicious_sip in value)
        {
	
	 sip_scanners[src] += 5; 

	log_reporter(fmt("sip_header if condition: %s", c$id),0); 
	@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )) 
		event SIP::w_m_BadUserAgent(c$id);
	@else
		sip_BadUserAgent(c$id);
	@endif	 

	} 

} 

function sip_BadUserAgent(cid: conn_id ) 
{ 

	log_reporter(fmt("sip_BadUserAgent: %s", cid),0);

	NOTICE([$note=SIP::BadUserAgent, $id=cid,
		$msg=fmt("Sipvicious Scan seen")]); 
               	#$suppress_for=6hrs, 
               	#$identifier=cat(cid$orig_h)]);
	
	sip_scanners[cid$orig_h]  += 5 ; 

@if ( Cluster::is_enabled() ) 
	log_reporter(fmt("sip_BadUserAgent calling m_w_add_sip_scanner: %s", cid),0);
	event SIP::m_w_add_sip_scanner(cid$orig_h);
@endif 

}



@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event SIP::w_m_BadUserAgent(cid: conn_id)
{

	log_reporter(fmt("w_m_BadUserAgent: %s", cid),0); 
        sip_BadUserAgent(cid);
}
@endif


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
