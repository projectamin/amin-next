package Amin::Proxy::RateLimit;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';

use Amin qw(NS);
use Class::Tiny qw(Proxy);
use Time::HiRes ();

# The per-IP rate limit — "may this client speak?" — as a static `begin`
# filter (proxy-plan §P5).  It is deliberately NOT an element-scoped _LazyGate
# candidate like Proxy::Route: a gate splices only ONE candidate per element,
# so two request-bound candidates would shadow each other instead of chaining,
# and a request the bucket lets through must still be routed.  As an
# element-agnostic begin filter it always sees <amin:request>, sits just above
# the routing gate, and a shed request is swallowed before any route is chosen
# — so a shed request never reaches a backend.
#
# Its parameters come from the injected `Proxy` (the compiled config) — the
# same shared context Proxy::Route reads — so no new injection channel exists
# (§10.2).  One front serves one profile per process, so the per-IP buckets are
# process-scoped class state: exactly the lifetime the `rps=0` "no refill"
# contract promises.
#
# A request over budget is closed-world denied — a -7100 <amin:status>, which
# the HTTP adapter maps to 429.  Not a silent drop, and not a backend hop.
use constant {
    RC_RATE_LIMITED => -7100,
};

our %BUCKETS;   # client IP => { tokens, last } — one front per process

sub name    { '' }        # element-agnostic: any document, any element
sub element { '' }

sub start_element ($self, $el) {
    my ($ns, $ln) = ($el->{NamespaceURI} // '', $el->{LocalName} // $el->{Name} // '');
    if ($ns eq NS() && $ln eq 'request') {
        # Within budget — let it flow on to be routed (never consumed here).
        return $self->SUPER::start_element($el) if $self->_allow($el);
        $self->_deny($el);
        $self->{_shed} = 1;             # swallow this element's close too
        return;
    }
    return $self->SUPER::start_element($el);
}

# A shed element is swallowed whole: the matching close is not forwarded either,
# so nothing downstream (the routing gate included) ever sees the request.
sub end_element ($self, $el) {
    my ($ns, $ln) = ($el->{NamespaceURI} // '', $el->{LocalName} // $el->{Name} // '');
    if ($ns eq NS() && $ln eq 'request' && delete $self->{_shed}) {
        return;
    }
    return $self->SUPER::end_element($el);
}

# Opt-in: no `rate-limit` declared (or no config injected) → always allow.  One
# bucket per client IP, refilled at `rps` tokens/second up to a `burst` cap; a
# request costs one token.  `rps=0` never refills, so a client gets exactly
# `burst` requests for the process's life.  The algorithm is the byte-for-byte
# peer of the Rust front's `RateLimiter::allow`, so a `rps=0` profile sheds the
# same request on both fronts (§7).
sub _allow ($self, $el) {
    my $rl = ($self->Proxy ? $self->Proxy->rate_limit : undef) or return 1;
    my %a   = _surface($el);
    my $ip  = $a{peer} // '';
    my $now = Time::HiRes::time();
    my $b   = $BUCKETS{$ip} //= { tokens => $rl->{burst}, last => $now };
    my $dt  = $now - $b->{last};
    $dt = 0 if $dt < 0;
    $b->{last} = $now;
    $b->{tokens} += $dt * $rl->{rps};
    $b->{tokens} = $rl->{burst} if $b->{tokens} > $rl->{burst};
    return 0 if $b->{tokens} < 1;
    $b->{tokens} -= 1;
    return 1;
}

sub _deny ($self, $el) {
    my %a   = _surface($el);
    my $ip  = $a{peer} // '';
    my $msg = "rate limit exceeded for peer=$ip";
    $self->Log && $self->Log->can('warn') && $self->Log->warn("proxy: $msg");
    my $h = $self->Handler or return;
    my $result = _event(NS(), 'amin', 'result');
    my $status = _event(NS(), 'amin', 'status',
        { rc => sprintf('%+d', RC_RATE_LIMITED), exit_kind => 'rate_limited', msg => $msg });
    $h->start_element($result);
    $h->start_element($status);
    $h->end_element($status);
    $h->end_element($result);
    return;
}

# SAX start/end event hashes.  Attributes are always amin-namespaced — the
# decision element is amin:, its attributes are the shared amin: vocabulary
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
