# Perlbal Google Authentication package
#
# This gives the ability to provide an authentication-required frontend to your Perlbal instance
# by configuring any service to use this plugin.  Once enabled on a service, any request that comes
# in must be authenticated before it is passed on to the rest of the handling in the service.
#
# This supports Google accounts, which allows for general gmail access as well as other domain
# access if you want to restrict it to your company domain, for example.
#
# To use, configure this on your service with the following commands:
#
#  SET googleauth.required      = on
#  SET googleauth.user_domain   = gmail.com
#  SET googleauth.cookie_domain = .foo.com
#
# Change user_domain to any other domain to restrict accounts to the domain specified.  Or leave
# that option out to not restrict.  The cookie_domain option sets the cookie's domain.  This is
# useful if you have many subdomains but you want to only force authentication once per user.
# Note the leading period.
#

package Perlbal::Plugin::GoogleAuth;

use strict;
use warnings;

use Carp;
use Perlbal;
use Net::Google::FederatedLogin;

# globals go here
our %Cnf;
our %Session;

# do nothing on load/unload
sub load   { 1 };
sub unload { 1 };

# called when we're being added to a service
sub register {
    my ($class, $svc) = @_;

    my $conf = sub {
        $Cnf{$svc->{name}} ||= { enabled => 0, user_domain => 'gmail.com' };
        $Cnf{$svc->{name}}->{$_[0]} = $_[1];
    };

    my $err = sub {
        my ($out, $msg, @args) = @_;
        $out->(sprintf("ERROR: $msg", @args))
            if defined $out;
        return 0;
    };

    # generic config setter
    my $set_conf = sub {
        my ($out, $what, $val) = @_;
        return 0 unless $what && $val;

        if ($what eq 'enabled') {
            $val = 1 if $val =~ /^(?:yes|on|true|1)$/;
            $val = 0 unless $val == 1;
        }

        if ($what eq 'return_to') {
            $val =~ s!/$!!;
            $val = "http://$val"
                unless $val =~ m!^https?://!;
        }

        $conf->( $what => $val );
        return 1;
    };

    # let the user configure our string values
    $svc->register_setter('GoogleAuth', 'user_domain', $set_conf);
    $svc->register_setter('GoogleAuth', 'cookie_domain', $set_conf);
    $svc->register_setter('GoogleAuth', 'return_to', $set_conf);
    $svc->register_setter('GoogleAuth', 'enabled', $set_conf);

    # now render our initial grabber
    $svc->register_hook('GoogleAuth', 'start_http_request', \&start_http_request);

    return 1;
}

# when a request initially starts, see if we need to do anything and, if so, then do the
# magic to redirect them and make the authentication happen
sub start_http_request {
    my Perlbal::ClientHTTPBase $req = $_[0];

    # ensure we're doing something with this request
    my $cnf = $Cnf{$req->{service}->{name}};
    return 0 unless defined $cnf && $cnf->{enabled};

    # now check to see if they have cookies
    my Perlbal::HTTPHeaders $hd = $req->{req_headers};
    my %cookies;
    foreach (split(/;\s+/, $hd->header("Cookie") || '')) {
        next unless /(.*)=(.*)/;
        $cookies{Perlbal::Util::durl($1)} = Perlbal::Util::durl($2);
    }

    # see if they have an auth cookie
    my $uri = $hd->request_uri;
    my $email = sid_valid($cookies{perlbal_sid} || '');
    if (defined $email) {
        # but if they are somehow at the auth pages, let's pass them through to the
        # final destination (na na na, na!)
        if ( $uri =~ m!^/_googleauth_(?:login|check)\?! ) {
            my ($page, $args) = parse_uri($uri);
            return $req->send_full_response(302, [ Location => $args->{uri} ], '');
        }

        # They are authorized, so put the header on and bounce them.
        $hd->header( 'X-Google-Account' => $email );
        return 0;
    }

    # at this point they're ours, so we can make destructive changes
    # to the request object if we need to.  for now, see if we have a query string
    # to figure out if they're logging in.
    return $req->_simple_response(404) if $uri =~ m!^/favicon\.ico!;
    return redirect($req, "/_googleauth_login", { uri => Perlbal::Util::durl($uri) })
        unless $uri =~ m!^/_googleauth_(?:login|check)\?!;

    # now we can dispatch appropriately
    my ($page, $args) = parse_uri($uri);

    # we don't know who they are, try to log them in
    if ($uri =~ m!^/_googleauth_login!) {
        return send_user_to_google($req, $hd, $args);
    }

    # came back from google, verify their ID
    elsif ($uri =~ m!^/_googleauth_check!) {
        return do_openid_verification($req, $hd, $args);
    }

    # if we fall through to here, something broke... so die
    return fatal_message($req, "Something wicked this way comes.");
}

# do the initial OpenID transaction
sub send_user_to_google {
    my Perlbal::ClientHTTPBase $req = shift;
    my Perlbal::HTTPHeaders $hd = shift;
    my ($args) = @_;

    my $cnf = $Cnf{$req->{service}->{name}};
    my $return_to = $cnf->{return_to} || '';
    $return_to ||= 'http://' . $hd->header('Host');

    my $goog = Net::Google::FederatedLogin->new(
        claimed_id => $cnf->{user_domain},
        return_to  => eurl($return_to . "/_googleauth_check?uri=" . eurl($args->{uri})),
            # double escaped above because the module does not escape this parameter
        extensions => [
            {
                ns          => 'ext1',
                uri         => 'http://openid.net/srv/ax/1.0',
                attributes  => {
                    mode        => 'fetch_request',
                    required    => 'email',
                    type        => {
                        email => 'http://axschema.org/contact/email'
                    }
                }
            }
        ],
    );

    my $check_url;
    eval {
        $check_url = $goog->get_auth_url;
    };
    if ($@) {
        Carp::cluck("Failure in sending the user to Google: $@");
        return fatal_message($req, "Internal failure authenticating your request.");
    }

    return redirect($req, $check_url);
}

# perform the final verification
sub do_openid_verification {
    my Perlbal::ClientHTTPBase $req = shift;
    my Perlbal::HTTPHeaders $hd = shift;
    my ($args) = @_;

    my $cnf = $Cnf{$req->{service}->{name}};
    my $return_to = $cnf->{return_to} || '';
    $return_to ||= 'http://' . $hd->header('Host');

    my $goog = Net::Google::FederatedLogin->new(
        cgi_params => $args,
        return_to  => $return_to . "/_googleauth_check?uri=" . eurl($args->{uri}),
    );

    my $vid;
    eval { $vid = $goog->verify_auth; };
    if ($@) {
        # Something bad happened, so the user is probably at an invalid state and we should
        # bounce them back to where they were trying to go. This will cause them to go through
        # the authentication step again. If this puts them in a redirect loop, the browser
        # will break them out of it. (Which is bad, but...)
        return $req->send_full_response(302, [ Location => $args->{uri} ], '');
    }

    return fatal_message($req, "Unverified user.") unless $vid;

    my $ext;
    eval { $ext = $goog->get_extension('http://openid.net/srv/ax/1.0'); };
    return fatal_message($req, "You must allow authentication to proceed.")
        unless $ext;

    my $email;
    eval { $email = $ext->get_parameter('value.email'); };
    return fatal_message($req, "Email not retrieved.")
        unless $email;

    return fatal_message($req, "You must be part of " . $cnf->{user_domain} . ".")
        unless $email =~ /\@$cnf->{user_domain}$/;

    # all good, so now we can set the verified cookie...
    my $rnd = rand_string();
    $Session{$rnd} = {
        last_use => time,
        owner    => $email,
        # more stuff here?
    };

    # done here, create the cookie and then redirect
    my $cookie = "perlbal_sid=$rnd";
    $cookie .= "; Domain=$cnf->{cookie_domain}"
        if exists $cnf->{cookie_domain};
    $cookie .= "; HttpOnly";
    return $req->send_full_response(302, [ Location => $args->{uri}, "Set-Cookie" => $cookie ], '');
}

# let the user know something went terribly awry
sub fatal_message {
    my ($req, $msg) = @_;
    return send_basic_page($req, "Fatal Error", $msg);
}

# send the user somewhere else (did I really have to comment this?  damn my
# comment OCD)
sub redirect {
    my Perlbal::ClientHTTPBase $req = shift;
    my ($uri, $qs) = @_;

    $qs ||= {};
    if (scalar %$qs) {
        $uri .= $uri =~ /\?/ ? '&' : '?';
        $uri .= join('&', map { $_ . '=' . eurl($qs->{$_}) } keys %$qs);
    }

    return $req->send_full_response(302, [ Location => $uri ], '');
}

# parse a uri (includes query string)
sub parse_uri {
    my $uri = $_[0];

    my ($loc, $qs) = split /\?/, $uri;
    return ($loc || '/', {})
        unless defined $qs && $qs;

    my $args = {};
    foreach my $pair (split /&/, $qs) {
        $args->{$1} = Perlbal::Util::durl($2)
            if $pair =~ /^(.+?)=(.+)$/;
    }
    return ($loc, $args);
}

# simply check to see if a session is valid. returns the email address of the account
# if it is. else, returns undef.
sub sid_valid {
    my $sid = $_[0];

    # if not a known session, we're done here
    return undef unless exists $Session{$sid};

    # validate this sid against our sessions.  for now, we just allow the presence of
    # a known sid to be enough.  we do not validate against IP.  we do have a requirement
    # of freshness, though, if it's been more than 24 hours we force a new log in.
    my $sess = $Session{$sid};
    if ($sess->{last_use} < time - 86400) {
        delete $Session{$sid};
        return undef;
    }

    # update the session and return
    $sess->{last_use} = time;
    return $sess->{owner};
}

# writes out the consistent part of the page
sub send_basic_page {
    my Perlbal::ClientHTTPBase $req = shift;
    my ($subj, $body) = @_;
    my $page = <<EOF;
<!DOCTYPE HTML>
<html>
<head><title>$subj</title></head>
<body>
    <h1>$subj</h1>
    $body
</body>
</html>
EOF
    return $req->send_full_response(200, [], \$page);
}

# called when we're no longer active on a service
sub unregister {
    my ($class, $svc) = @_;
    $svc->unregister_hooks('GoogleAuth');
    $svc->unregister_setters('GoogleAuth');
    return 1;
}

# encode for a URL.  not sure why Perlbal provides durl but not eurl.
sub eurl {
    my $a = $_[0];
    $a =~ s/([^a-zA-Z0-9_\,\-.\/\\\: ])/uc sprintf("%%%02x",ord($1))/eg;
    $a =~ tr/ /+/;
    return $a;
}

# generate a cookie string
sub rand_string {
    my @chars = ('a'..'z', 'A'..'Z', '0'..'9');
    return join('', map { $chars[int(rand(62))] } 1..32);
}

1;
