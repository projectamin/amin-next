package Amin::Proxy::Route;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';

use Amin qw(NS);
use Class::Tiny qw(Proxy);

# The routing filter — "where does this profile go?", as a `begin` candidate
# bound to <amin:request> (proxy-plan §5.1/§5.2).  Being a _LazyGate candidate,
# it splices in only on a document that actually carries a request, and it
# lands BELOW the static begin filters — so ZCap always authorizes before a
# route is chosen, with no ordering convention to get wrong.
#
# It owns no table.  The compiled matcher is injected as `Proxy` — the same
# channel that injects `Render` — compiled once at boot by Amin::Proxy::Config
# and reused across requests (§5.3).  A request stream never re-emits routes or
# backends; that redundant per-request data flow is exactly what §5.3 rejects.
#
# On <amin:request> it emits one <proxy:backend> per candidate backend, in the
# route's declared order, each carrying the route's policy; choosing among them
# is the balancer's job (§5.4), not the router's.  The decision is
# adapter-facing: `proxy:` is a namespace no filter consumes.
#
# A request that matches no route is closed-world denied — a -6150
# <amin:status>, never a silent default to some backend.
use constant {
    PROXY_NS     => 'http://projectamin.org/ns/proxy/1',
    PROXY_PREFIX => 'proxy',
    RC_NO_ROUTE  => -6150,
};

sub name    { '' }        # element-only binding: any <amin:request>
sub element { 'request' }

sub start_element ($self, $el) {
    my ($ns, $ln) = ($el->{NamespaceURI} // '', $el->{LocalName} // $el->{Name} // '');
    if ($ns eq NS() && $ln eq 'request') {
        $self->_route($el);
    }
    return $self->SUPER::start_element($el);
}

sub _route ($self, $el) {
    my %a    = _surface($el);
    my $host = $a{host} // '';
    my $path = $a{path} // '/';

    my $cfg = $self->Proxy;
    my $route = $cfg ? $cfg->match(host => $host, path => $path) : undef;
    return $self->_deny($host, $path, $cfg ? 'no_route' : 'no_proxy_config')
        unless $route;

    $self->_backend($_, $route) for $route->{to}->@*;
    return 1;
}

# One decision element per candidate backend: the transport and destination,
# plus the route-level directives so the adapter needs nothing else.
sub _backend ($self, $b, $route) {
    my $h = $self->Handler or return;
    my $attrs = {
        id        => $b->{id},
        transport => $b->{transport},
        (defined $b->{peer} ? (peer => $b->{peer}) : (addr => $b->{addr})),
        policy         => $route->{policy},
        'strip-prefix' => $route->{strip_prefix} ? 'true' : 'false',
        ws             => $route->{ws} ? 'on' : 'off',
    };
    my $ev = _event(PROXY_NS, PROXY_PREFIX, 'backend', $attrs);
    $h->start_element($ev);
    $h->end_element($ev);
    return;
}

sub _deny ($self, $host, $path, $why) {
    my $msg = sprintf 'no route for host=%s path=%s (%s)', $host, $path, $why;
    $self->Log && $self->Log->can('warn') && $self->Log->warn("proxy: $msg");
    my $h = $self->Handler or return;
    my $result = _event(NS(), 'amin', 'result');
    my $status = _event(NS(), 'amin', 'status',
        { rc => sprintf('%+d', RC_NO_ROUTE), exit_kind => $why, msg => $msg });
    $h->start_element($result);
    $h->start_element($status);
    $h->end_element($status);
    $h->end_element($result);
    return;
}

# SAX start/end event hashes.  Attributes are always amin-namespaced — the
# decision element is proxy:, its attributes are the shared amin: vocabulary
# (proxy-plan §4.3), so there is one attribute namespace, not two.
sub _event ($uri, $prefix, $local, $attrs = undef) {
    my %e = (NamespaceURI => $uri, LocalName => $local,
             Name => "$prefix:$local", Prefix => $prefix);
    if ($attrs) {
        my $auri = NS();
        my %A;
        for my $k (keys %$attrs) {
            $A{"$auri$k"} = {
                Name         => "amin:$k",
                LocalName    => $k,
                Prefix       => 'amin',
                NamespaceURI => $auri,
                Value        => defined $attrs->{$k} ? '' . $attrs->{$k} : '',
            };
        }
        $e{Attributes} = \%A;
    }
    return \%e;
}

sub _surface ($el) {
    my %a;
    for my $k (keys %{ $el->{Attributes} // {} }) {
        my $h = $el->{Attributes}{$k} // {};
        my $n = $h->{LocalName} // $h->{Name} // $k;
        $a{$n} = $h->{Value};
    }
    return %a;
}

1;
