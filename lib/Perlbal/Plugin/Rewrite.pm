###########################################################################
# plugin to use to do URI/host/header rewriting
#
# this plugin is designed to run first, before anything else.  to do that,
# make sure you load it before you load vpath/vhost/whatever else.  this
# should be first in the plugin order:
#
#   SET service.plugins = rewrite, vpaths
#
# using this plugin is easy.  once it's active on a service:
#
#   REWRITE <thing> [service] <from> = <to> [options]
#
# some examples:
#
#   REWRITE URI web ^/foo(/.*)$ = /\0
#   REWRITE URI web .           = http://google.com/   [R]
#
###########################################################################

package Perlbal::Plugin::Rewrite;

use strict;
use warnings;
no  warnings qw(deprecated);

our %Services;  # service_name => $svc

# when "LOAD" directive loads us up
sub load {
    my $class = shift;

    Perlbal::register_global_hook('manage_command.rewrite', sub {
        my $mc = shift->parse(qr/^rewrite\s+(uri)\s+(?:(\w+)\s+)?(\S+)\s*=\s*(\S+)(?:\s+\[(\w+?)\]\s*)?$/,
                              "usage: REWRITE URI [service] <regex> = <regex> [options]");
        my ($type, $selname, $regex, $target, $opts) = $mc->args;
        unless ($selname ||= $mc->{ctx}{last_created}) {
            return $mc->err("omitted service name not implied from context");
        }

        my $ss = Perlbal->service($selname);
        my $cregex = qr/$regex/;
        return $mc->err("invalid regular expression: '$regex'")
            unless $cregex;

        $ss->{extra_config}->{_rewrite} ||= [];
        push @{$ss->{extra_config}->{_rewrite}}, [ lc $type, $cregex, $target, uc $opts ];

        return $mc->ok;
    });

    return 1;
}

# unload our global commands, clear our service object
sub unload {
    my $class = shift;

    Perlbal::unregister_global_hook('manage_command.rewrite');
    unregister($class, $_) foreach (values %Services);
    return 1;
}

# called when we're being added to a service
sub register {
    my ($class, $svc) = @_;

    $svc->{extra_config}->{_rewrite} = [];
    $svc->register_hook('Rewrite', 'start_http_request', \&start_http_request);
    $Services{"$svc"} = $svc;
    return 1;
}

# called when we're no longer active on a service
sub unregister {
    my ($class, $svc) = @_;

    $svc->{extra_config}->{_rewrite} = undef;
    $svc->unregister_hook('Rewrite', 'start_http_request');
    delete $Services{"$svc"};
    return 1;
}

# call back from Service via ClientHTTPBase's event_read calling service->select_new_service(Perlbal::ClientHTTPBase)
sub start_http_request {
    my Perlbal::ClientHTTPBase $cb = $_[0];

    # get headers
    my $req = $cb->{req_headers};
    return $cb->_simple_response(404, "Not Found (no reqheaders)") unless $req;

    # we're probably going to need the URI too, and get our maps
    my $uri = $req->request_uri;
    my $maps = $cb->{service}->{extra_config}->{_rewrite} ||= {};

    # DEBUG
    print "[rewrite] $uri\n";

    # iterate down the list of paths, find any matches
    foreach my $row (@$maps) {
        my $matched = 0;

        # rewrite URI if we're told to
        if ($row->[0] eq 'uri') {
            my @parts;
            next unless @parts = ($uri =~ /$row->[1]/);

            $matched = 1;
            print "[rewrite] MATCHED: $uri => ";
            $uri = $row->[2];
            $uri =~ s/\\(\d)/$parts[$1] || ''/eg;
            print "$uri";
            $req->set_request_uri($uri);
        }

        # bail now if this rule didn't match
        next unless $matched;

        # now if we're told to redirect, or to end, then do so if this rule matched
        if (index($row->[3], 'R') >= 0) {
            print "... redirect!\n";
            return $cb->send_full_response(302, [ Location => $uri ], '');
        } elsif (index($row->[3], 'L') >= 0) {
            print "... finally!\n";
            return 0;
        }

        # DEBUG ALL THE THINGS
        print "\n";
    }

    return 0;
}

1;
