
class iRuleLexer(RegexLexer):
    """
    For iRule source code.

    *New in Pygments 0.10.*
    """

    keyword_cmds_re = (
        r'\b(if|while|for|catch|return|break|continue|switch|exit|foreach|ACCESS_ACL_ALLOWED|ACCESS_ACL_DENIED|ACCESS_POLICY_AGENT_EVENT|ACCESS_POLICY_COMPLETED|ACCESS_SESSION_CLOSED|ACCESS_SESSION_STARTED|ADAPT_REQUEST_RESULT|ADAPT_RESPONSE_RESULT|ACCESS_ACL_ALLOWED|ACCESS_ACL_DENIED|ACCESS_POLICY_AGENT_EVENT|ACCESS_POLICY_COMPLETED|ACCESS_SESSION_CLOSED|ACCESS_SESSION_STARTED|ASM_REQUEST_BLOCKING|ASM_REQUEST_DONE|ASM_REQUEST_VIOLATION|ASM_RESPONSE_VIOLATION|IN_DOSL7_ATTACK|CACHE_REQUEST|CACHE_RESPONSE|CACHE_UPDATE|CLASSIFICATION_DETECTED|DIAMETER_INGRESS|DIAMETER_EGRESS|DNS_REQUEST|DNS_RESPONSE|IN_DOSL7_ATTACK|FIX_MESSAGE|FLOW_INIT|FLOW_INIT|LB_FAILED|LB_SELECTED|NAME_RESOLVED|PERSIST_DOWN|RULE_INIT|DNS_REQUEST|DNS_RESPONSE|LB_FAILED|LB_SELECTED|RULE_INIT|HTML_COMMENT_MATCHED |HTML_TAG_MATCHED|HTTP_CLASS_FAILED|HTTP_CLASS_SELECTED|HTTP_DISABLED|HTTP_PROXY_REQUEST|HTTP_REQUEST|HTTP_REQUEST_DATA|HTTP_REQUEST_SEND|HTTP_RESPONSE|HTTP_RESPONSE_CONTINUE|HTTP_RESPONSE_DATA|HTTP_REQUEST_RELEASE|HTTP_RESPONSE_RELEASE|ICAP_REQUEST|ICAP_RESPONSE|CLIENT_ACCEPTED|CLIENT_CLOSED|CLIENT_DATA|CLIENTSSL_DATA|SERVER_CLOSED|SERVER_CONNECTED|SERVER_DATA|SERVERSSL_DATA|LB_FAILED|LB_SELECTED|LB_QUEUED|NAME_RESOLVED|PCP_REQUEST|PCP_RESPONSE|QOE_PARSE_DONE|REWRITE_REQUEST_DONE|REWRITE_RESPONSE_DONE|RTSP_REQUEST|RTSP_REQUEST_DATA|RTSP_RESPONSE|RTSP_RESPONSE_DATA|CLIENT_ACCEPTED|CLIENT_CLOSED|CLIENT_DATA|CLIENTSSL_DATA|SERVER_CLOSED|SERVER_CONNECTED|SERVER_DATA|SERVERSSL_DATA|SIP_REQUEST|SIP_REQUEST_SEND|SIP_RESPONSE|SIP_RESPONSE_SEND|SOCKS_REQUEST|CLIENTSSL_CLIENTCERT|CLIENTSSL_CLIENTHELLO|CLIENTSSL_DATA|CLIENTSSL_HANDSHAKE|CLIENTSSL_SERVERHELLO_SEND|SERVERSSL_CLIENTHELLO_SEND|SERVERSSL_DATA|SERVERSSL_HANDSHAKE|SERVERSSL_SERVERHELLO|STREAM_MATCHED|CLIENT_ACCEPTED|CLIENT_CLOSED|CLIENT_DATA|CLIENTSSL_DATA|SERVER_CLOSED|SERVER_CONNECTED|SERVER_DATA|SERVERSSL_DATA|USER_REQUEST|USER_RESPONSE|CLIENT_ACCEPTED|CLIENT_CLOSED|CLIENT_DATA|SERVER_CLOSED|SERVER_CONNECTED|SERVER_DATA)\b'
        )

    builtin_cmds_re = (
        r'\b(ACCESS::acl|ACCESS::disable|ACCESS::enable|ACCESS::policy|ACCESS::respond|ACCESS::restrict_irule_events|ACCESS::session|ACCESS::user|ACCESS::uuid|active_members|active_nodes|ADAPT::allow|ADAPT::enable|ADAPT::preview_size|ADAPT::result|ADAPT::select|ADAPT::service_down_action|ADAPT::timeout|AES::decrypt|AES::encrypt|AES::key|after|append|array|ASM::client_ip|ASM::disable|ASM::enable|ASM::payload|ASM::raise|ASM::severity|ASM::status|ASM::support_id|ASM::unblock|ASM::violation_data|ASN1::decode|ASN1::element|ASN1::encode|AUTH::abort|AUTH::authenticate_continue|AUTH::cert_credential|AUTH::cert_issuer_credential|AUTH::last_event_session_id|AUTH::password_credential|AUTH::response_data|AUTH::ssl_cc_ldap_status|AUTH::ssl_cc_ldap_username|AUTH::start|AUTH::status|AUTH::subscribe|AUTH::unsubscribe|AUTH::username_credential|AUTH::wantcredential_prompt_style|AUTH::wantcredential_type|auto_execok|auto_import|auto_load|auto_mkindex_old|auto_qualify|auto_reset|AVR::disable|AVR::enable|b64decode|b64encode|bgerror|binary|BWC::color|BWC::mark|BWC::policy|BWC::rate|CACHE::accept_encoding|CACHE::age|CACHE::disable|CACHE::enable|CACHE::expire|CACHE::headers|CACHE::hits|CACHE::payload|CACHE::priority|CACHE::uri|CACHE::useragent|CACHE::userkey|call|CATEGORY::lookup|cd|classIFICATION::app|CLASSIFICATION::category|CLASSIFICATION::disabled|CLASSIFICATION::enabled|CLASSIFICATION::protocol|CLASSIFICATION::urlcat|CLASSIFY::application|CLASSIFY::category|CLASSIFY::defer|client_addr|client_port|clientside|clock|clone|close|COMPRESS::buffer_size|COMPRESS::disable|COMPRESS::enable|COMPRESS::gzip|COMPRESS::method|concat|connect info|cpu|crc32|CRYPTO::decrypt|CRYPTO::encrypt|CRYPTO::hash|CRYPTO::keygen|CRYPTO::sign|CRYPTO::verify|dde|decode_uri|DEMANGLE::disable|DEMANGLE::enable|DIAMETER::avp|DIAMETER::command|DIAMETER::disconnect|DIAMETER::drop|DIAMETER::header|DIAMETER::host|DIAMETER::is_request|DIAMETER::is_response|DIAMETER::length|DIAMETER::payload|DIAMETER::realm|DIAMETER::respond|DIAMETER::result|DIAMETER::session|discard|discard|DNS::additional|DNS::answer|DNS::authority|DNS::class|DNS::disable|DNS::drop|DNS::edns0|DNS::enable|DNS::header|DNS::is_wideip|DNS::last_act|DNS::len|DNS::name|DNS::origin|DNS::ptype|DNS::query|DNS::question|DNS::rdata|DNS::return|DNS::rr|DNS::rrname|DNS::rrtype|DNS::scrape|DNS::tsig|DNS::ttl|DNS::type|domain|DOSL7::disable|DOSL7::enable|DOSL7::profile|drop|DSLITE::remote_addr|encoding|eof|error|eval|event|exec|expr|fblocked|fconfigure|fcopy|fileevent|filename|findstr|FIX::field|FIX::tag|FLOW::priority|flush|format|forward|FTP::port|getfield|gets|global|HA::status|history|HSL::open|HSL::send|HTML::comment |HTML::disable|HTML::enable|HTML::tag attribute|htonl|htons|http|HTTP::class|HTTP::close|HTTP::collect|HTTP::cookie|HTTP::disable|HTTP::enable|HTTP::fallback|HTTP::header|HTTP::host|HTTP::is_keepalive|HTTP::is_redirect|HTTP::method|HTTP::passthrough_reason|HTTP::password|HTTP::path|HTTP::payload|HTTP::query|HTTP::redirect|HTTP::release|HTTP::request_num|HTTP::respond|HTTP::retry|HTTP::status|HTTP::uri|HTTP::username|HTTP::version|http_cookie|http_header|http_host|http_method|http_uri|http_version|ICAP::header|ICAP::method|ICAP::status|ICAP::uri|ifile|imid|incr|info|interp|IP::addr|IP::client_addr|IP::hops|IP::idle_timeout|IP::local_addr|IP::protocol|IP::remote_addr|IP::reputation|IP::server_addr|IP::stats|IP::tos|IP::ttl|IP::version|ip_protocol|ip_tos|ip_ttl|ISESSION::deduplication|ISTATS::get|ISTATS::incr|ISTATS::remove|ISTATS::set|join|lappend|lasthop|LB::bias|LB::class|LB::command|LB::connect|LB::context_id|LB::detach|LB::down|LB::dst_tag|LB::mode|LB::persist|LB::prime|LB::queue|LB::reselect|LB::select|LB::server|LB::snat|LB::src_tag|LB::status|LB::up|library|lindex|LINK::lasthop|LINK::nexthop|LINK::qos|LINK::vlan_id|link_qos|linsert|listen|llength|llookup|load|local_addr|log|lrange|lreplace|lsearch|lset|LSN::address|LSN::disable|LSN::inbound-entry|LSN::persistence-entry|LSN::pool|LSN::port|lsort|md5|members|memory|msgcat|NAME::lookup|NAME::response|namespace|nexthop|node|nodes|NTLM::disable|NTLM::enable|ntohl|ntohs|ONECONNECT::detach|ONECONNECT::label|ONECONNECT::reuse|open|Operators|package|parray|PCP::reject|PCP::request|PCP::response|peer|persist|pid|pkg::create|pkg_mkIndex|POLICY::controls|POLICY::names|POLICY::rules|POLICY::targets|pool|priority|proc|PROFILE::auth|PROFILE::clientssl|PROFILE::diameter|PROFILE::exists|PROFILE::fast L4|PROFILE::fasthttp|PROFILE::ftp|PROFILE::httpclass|PROFILE::httpcompression|PROFILE::oneconnect|PROFILE::persist|PROFILE::serverssl|PROFILE::stream|PROFILE::tcp|PROFILE::udp|PROFILE::webacceleration|PROFILE::xml|puts|pwd|QOE::disable|QOE::enable|QOE::video|RADIUS::avp|RADIUS::code|RADIUS::id|rateclass|re_syntax|read|recv|redirect|registry|reject|relate_client|relate_server|remote_addr|rename|RESOLV::lookup|resource|return|REWRITE::disable|REWRITE::enable|REWRITE::payload|REWRITE::post_process|rmd160|ROUTE::age|ROUTE::bandwidth|ROUTE::domain|ROUTE::rttvar|RTSP::collect|RTSP::header|RTSP::method|RTSP::msg_source|RTSP::payload|RTSP::release|RTSP::respond|RTSP::status|RTSP::uri|RTSP::version|SafeBase|scan|SCTP::client_port|SCTP::collect|SCTP::local_port|SCTP::mss|SCTP::payload|SCTP::ppi|SCTP::release|SCTP::remote_port|SCTP::respond|SCTP::server_port|SDP::field|SDP::media|SDP::session_id|seek|send|server_addr|server_port|serverside|session|set|sha1|sha256|sha384|sha512|sharedvar|SIP::call_id|SIP::discard|SIP::from|SIP::header|SIP::method|SIP::payload|SIP::respond|SIP::response|SIP::to|SIP::uri|SIP::via|SMTPS::disable|SMTPS::enable|snat|snatpool|socket|SOCKS::allowed|SOCKS::destination|SOCKS::version|source|split|SSL::authenticate|SSL::cert|SSL::cipher|SSL::collect|SSL::disable|SSL::enable|SSL::extensions|SSL::forward_proxy|SSL::handshake|SSL::is_renegotiation_secure|SSL::mode|SSL::modssl_sessionid_headers|SSL::payload|SSL::profile|SSL::release|SSL::renegotiate|SSL::respond|SSL::secure_renegotiation|SSL::sessionid|SSL::sessionticket|SSL::unclean_shutdown|SSL::verify_result|static|STATS::get|STATS::incr|STATS::setmax|STATS::setmin|STREAM::disable|STREAM::enable|STREAM::encoding|STREAM::expression|STREAM::match|STREAM::max_matchsize|STREAM::replace|string|substr|table|Tcl_endOfWord|tcl_findLibrary|tcl_platform|tcl_startOfNextWord|tcl_startOfPreviousWord|tcl_wordBreakAfter|tcl_wordBreakBefore|tcltest|tclvars|TCP::bandwidth|TCP::client_port|TCP::close|TCP::collect|TCP::local_port|TCP::mss|TCP::nagle|TCP::notify|TCP::offset|TCP::option|TCP::payload|TCP::release|TCP::remote_port|TCP::respond|TCP::rtt|TCP::server_port|TCP::unused_port|tell|time|timing|TMM::cmp_cluster_primary|TMM::cmp_count|TMM::cmp_group|TMM::cmp_unit|trace|traffic_group|translate|UDP::client_port|UDP::drop|UDP::local_port|UDP::mss|UDP::payload|UDP::remote_port|UDP::respond|UDP::server_port|UDP::unused_port|unknown|unset|update|uplevel|upvar|URI::basename|URI::compare|URI::decode|URI::encode|URI::host|URI::path|URI::port|URI::protocol|URI::query|use|variable|virtual|vlan_id|vwait|WAM::disable|WAM::enable|WEBSSO::disable|WEBSSO::enable|WEBSSO::select|when|whereis|X509::cert_fields|X509::extensions|X509::hash|X509::issuer|X509::not_valid_after|X509::not_valid_before|X509::serial_number|X509::signature_algorithm|X509::subject_public_key|X509::subject_public_key_RSA_bits|X509::subject_public_key_type|X509::verify_cert_error_string|X509::version|X509::whole)\b'
        )

    name = 'iRules'
    aliases = ['iRule']
    filenames = ['*.irul', '*.irule']
    mimetypes = ['text/x-tcl', 'text/x-script.tcl', 'application/x-tcl']

    def _gen_command_rules(keyword_cmds_re, builtin_cmds_re, context=""):
        return [
            (keyword_cmds_re, Keyword, 'params' + context),
            (builtin_cmds_re, Name.Builtin, 'params' + context),
            (r'([\w\.\-]+)', Name.Variable, 'params' + context),
            (r'#', Comment, 'comment'),
        ]

    tokens = {
        'root': [
            include('command'),
            include('basic'),
            include('data'),
            (r'}', Keyword),  # HACK: somehow we miscounted our braces
        ],
        'command': _gen_command_rules(keyword_cmds_re, builtin_cmds_re),
        'command-in-brace': _gen_command_rules(keyword_cmds_re,
                                               builtin_cmds_re,
                                               "-in-brace"),
        'command-in-bracket': _gen_command_rules(keyword_cmds_re,
                                                 builtin_cmds_re,
                                                 "-in-bracket"),
        'command-in-paren': _gen_command_rules(keyword_cmds_re,
                                               builtin_cmds_re,
                                               "-in-paren"),
        'basic': [
            (r'\(', Keyword, 'paren'),
            (r'\[', Keyword, 'bracket'),
            (r'\{', Keyword, 'brace'),
            (r'"', String.Double, 'string'),
            (r'(eq|ne|in|ni)\b', Operator.Word),
            (r'!=|==|<<|>>|<=|>=|&&|\|\||\*\*|[-+~!*/%<>&^|?:]', Operator),
        ],
        'data': [
            (r'\s+', Text),
            (r'0x[a-fA-F0-9]+', Number.Hex),
            (r'0[0-7]+', Number.Oct),
            (r'\d+\.\d+', Number.Float),
            (r'\d+', Number.Integer),
            (r'\$([\w\.\-\:]+)', Name.Variable),
            (r'([\w\.\-\:]+)', Text),
        ],
        'params': [
            (r';', Keyword, '#pop'),
            (r'\n', Text, '#pop'),
            (r'(else|elseif|then)\b', Keyword),
            include('basic'),
            include('data'),
        ],
        'params-in-brace': [
            (r'}', Keyword, ('#pop', '#pop')),
            include('params')
        ],
        'params-in-paren': [
            (r'\)', Keyword, ('#pop', '#pop')),
            include('params')
        ],
        'params-in-bracket': [
            (r'\]', Keyword, ('#pop', '#pop')),
            include('params')
        ],
        'string': [
            (r'\[', String.Double, 'string-square'),
            (r'(?s)(\\\\|\\[0-7]+|\\.|[^"\\])', String.Double),
            (r'"', String.Double, '#pop')
        ],
        'string-square': [
            (r'\[', String.Double, 'string-square'),
            (r'(?s)(\\\\|\\[0-7]+|\\.|\\\n|[^\]\\])', String.Double),
            (r'\]', String.Double, '#pop')
        ],
        'brace': [
            (r'}', Keyword, '#pop'),
            include('command-in-brace'),
            include('basic'),
            include('data'),
        ],
        'paren': [
            (r'\)', Keyword, '#pop'),
            include('command-in-paren'),
            include('basic'),
            include('data'),
        ],
        'bracket': [
            (r'\]', Keyword, '#pop'),
            include('command-in-bracket'),
            include('basic'),
            include('data'),
        ],
        'comment': [
            (r'.*[^\\]\n', Comment, '#pop'),
            (r'.*\\\n', Comment),
        ],
    }

    def analyse_text(text):
        return shebang_matches(text, r'(tcl)')
