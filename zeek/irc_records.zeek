@load scripts/irc_whois.zeek
@load scripts/irc_privmsg.zeek
@load scripts/irc_usermsg.zeek
@load scripts/irc_join.zeek

module Strato;

event irc_channel_info(c: connection, is_orig: bool, chans: count) {
    print "channel info";
}

# Command: INVITE
# Parameters: <nickname> <channel>
# 
# The INVITE command is used to invite a user to a channel.  The
# parameter <nickname> is the nickname of the person to be invited to
# the target channel <channel>.  There is no requirement that the
# channel the target user is being invited to must exist or be a valid
# channel.  However, if the channel exists, only members of the channel
# are allowed to invite other users.  When the channel has invite-only
# flag set, only channel operators may issue INVITE command.
event irc_invite_message(c: connection, is_orig: bool, prefix: string, nickname: string, channel: string) {
    print "invite";
}

# Command: KICK
# Parameters: <channel> *( "," <channel> ) <user> *( "," <user> )
#             [<comment>]
# 
# The KICK command can be used to request the forced removal of a user
# from a channel.  It causes the <user> to PART from the <channel> by
# force.  For the message to be syntactically correct, there MUST be
# either one channel parameter and multiple user parameter, or as many
# channel parameters as there are user parameters.  If a "comment" is
# given, this will be sent instead of the default message, the nickname
# of the user issuing the KICK.
event irc_kick_message(c: connection, is_orig: bool, prefix: string, chans: string, users: string, comment: string) {
    print "kick";   
}

# Command: WHO
# Parameters: [ <mask> [ "o" ] ]
# The WHO command is used by a client to generate a query which returns
# a list of information which 'matches' the <mask> parameter given by
# the client.  In the absence of the <mask> parameter, all visible
# (users who aren't invisible (user mode +i) and who don't have a
# common channel with the requesting client) are listed.  The same
# result can be achieved by using a <mask> of "0" or any wildcard which
# will end up matching every visible user.
# 
# The <mask> passed to WHO is matched against users' host, server, real
# name and nickname if the channel <mask> cannot be found.
event irc_who_line(c: connection, is_orig: bool, target_nick: string, channel: string, user: string, host: string, server: string, nick: string, params: string, hops: count, real_name: string) {
    print "who line";
}


event irc_who_message(c: connection, is_orig: bool, mask: string, oper: bool) {
    print "who msg";   
}

