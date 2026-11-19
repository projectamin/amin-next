# A minimal PSGI adapter — bench-only.
#
# The framework ships NO PSGI path: the origin is Amin::AXA::Serve over
# Amin::Net::Loop (axa-plan §4.8).  This file exists solely so the *previous*
# origin (Starman) can be measured against the loop origin with the same app
# bundle, the same `Amin::AXA::HTTP` core and the same off-heap store.  It is
# the A/B control, not a supported entry point; nothing in perl-lib/ or bin/
# loads it.
#
# It is deliberately thin: `Amin::AXA::HTTP` is transport-neutral, so building
# a request hash from a Plack env and handing back the response is the whole
# adapter — and `render_stream`'s coderef already follows the PSGI streaming
# contract (call `$responder->(\@status_headers)`, write to the writer it
# returns), so it is returned to Starman unmodified.
use v5.38; use warnings; use utf8;

use Cwd qw(abs_path);
use File::Basename qw(dirname);

# `use lib` would run at compile time, before $root is assigned — so resolve
# the tree root and splice @INC at runtime, before the requires below.
my $root = $ENV{AMIN_ROOT} // dirname(dirname(abs_path(__FILE__)));
unshift @INC, "$root/perl-lib";

require Amin::AXA::HTTP;
require Amin::AXA::Store::SQLite;

my $app_dir = $ENV{AXA_APP_DIR} // "$root/examples/apps/shop-ui";
my $store = defined $ENV{AXA_STORE}
    ? Amin::AXA::Store::SQLite->new(path => $ENV{AXA_STORE})
    : Amin::AXA::Store->new;
my $ctx = Amin::AXA::HTTP->boot(app_dir => $app_dir, store => $store, stream => 1);

sub env_req ($env) {
    my (@headers, %folded);
    for my $k (keys %$env) {
        next unless $k =~ /^HTTP_([A-Z0-9_]+)$/;
        my $name = join '-', map { ucfirst lc } split /_/, $1;
        push @headers, [$name, $env->{$k}];
        $folded{ lc $name } = $env->{$k};
    }
    for my $pair (['Content-Type', 'CONTENT_TYPE'], ['Content-Length', 'CONTENT_LENGTH']) {
        next unless defined $env->{ $pair->[1] };
        push @headers, [$pair->[0], $env->{ $pair->[1] }];
        $folded{ lc $pair->[0] } = $env->{ $pair->[1] };
    }
    my $len  = $env->{CONTENT_LENGTH} // 0;
    my $body = '';
    read $env->{'psgi.input'}, $body, $len if $len > 0;
    return {
        method   => $env->{REQUEST_METHOD} // 'GET',
        path     => $env->{PATH_INFO}      // '/',
        query    => $env->{QUERY_STRING},
        version  => (($env->{SERVER_PROTOCOL} // '') =~ /1\.(\d)/ ? $1 : '1'),
        headers  => \@headers,
        header   => \%folded,
        host     => $env->{HTTP_HOST} // $env->{SERVER_NAME} // 'localhost',
        scheme   => $env->{'psgi.url_scheme'} // 'http',
        peer     => $env->{REMOTE_ADDR} // '0.0.0.0',
        body     => $body,
        body_overflow => 0,
    };
}

# Amin::AXA::HTTP->handle returns either the buffered triple
# `[$status, \@headers, $body_scalar]` or, when streaming, a coderef the
# transport drives.  Starman's delayed-response path is exactly that
# interface — it calls the coderef with a responder, and `$responder->([$s,$h])`
# returns a writer — so the streaming coderef is returned unmodified.  The
# buffered triple only needs its scalar body wrapped in an arrayref for PSGI.
sub app ($env) {
    my $res = Amin::AXA::HTTP->handle($ctx, env_req($env), stream => 1);
    return $res if ref $res eq 'CODE';
    my ($status, $headers, $body) = @$res;
    return [ $status, $headers, [ $body ] ];
}

\&app;    # a .psgi file must *return* the app coderef, not merely define it
