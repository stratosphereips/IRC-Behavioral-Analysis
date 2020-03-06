@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato4;

type irc_who_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    nick: string &log;
    user: string &log;
    host: string &log;
    real_name: string &log;
};

global irc_who_vec: vector of irc_who_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato4::LOG, [$columns=irc_who_record, $path="irc_whois"]);
}

event zeek_done() {
   for (i in irc_who_vec) {
       Log::write( Strato4::LOG, irc_who_vec[i]);
   }
}

# Command: WHOIS
# Parameters: [ <target> ] <mask> *( "," <mask> )
# 
# This command is used to query information about particular user.
# The server will answer this command with several numeric messages
# indicating different statuses of each user which matches the mask (if
# you are entitled to see them).  If no wildcard is present in the
# <mask>, any information about that nick which you are allowed to see
# is presented.
event irc_whois_channel_line(c: connection, is_orig: bool, nick: string, chans: string_set) {
    print "whois channel line"; 
}

event irc_whois_operator_line(c: connection, is_orig: bool, nick: string) {
    print "whois operator line";   
}

event irc_whois_user_line (c: connection, is_orig: bool, nick: string, user: string, host: string, real_name: string) {
    local rec: irc_who_record = irc_who_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $nick=nick, $user=user, $host=host, $real_name=real_name);
    irc_who_vec += rec;
    print "whois user line";   
}