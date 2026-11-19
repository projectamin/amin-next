package Amin::Proxy::Backend;
use v5.38; use warnings; use utf8; use experimental 'signatures';

# Backend runtime state and the balancer (proxy-plan §4.1/§5.4).
#
# A declared <amin:backend> is pure data — id, transport, peer|addr, hc.  What
# the adapter needs on top of that is *health*: a latency estimate and an
# in-flight count, so several candidate backends can be balanced.  That state
# is not in the config (the config is the immutable contract, §5.3); it lives
# here, one runtime record per declared id, owned by a route provider and
# reused across requests.
#
# The policy is the same `p2c_ewma` the <lb> vocabulary names: power-of-two
# choices over an EWMA of observed latency.  Two candidates are sampled at
# random and the lower-scoring one wins, which bounds the worst-case load
# without a global coordinator.  This is the one L7 balancing implementation;
# a route that names a different policy keeps the choice, it just is not
# exercised until that policy is implemented here.

# Score of a backend with an unmeasured latency: peers that have never answered
# must still be tried (exploration), so an unknown backend scores as one
# nominal unit rather than as infinitely good or infinitely bad.
use constant DEFAULT_EWMA => 1.0;   # seconds
# EWMA weight: ~last five samples dominate.  Small enough to react, large
# enough that one slow response does not evict a healthy backend.
use constant ALPHA => 0.2;
# Consecutive connect failures before a backend is considered down.
use constant MAX_FAILS => 3;

sub new ($class, $record) {
    return bless {
        %$record,
        ewma     => undef,   # undef = never measured
        inflight => 0,
        fails    => 0,
        served   => 0,
    }, $class;
}

sub id        ($self) { $self->{id} }
sub transport ($self) { $self->{transport} }
sub addr      ($self) { $self->{addr} }
sub peer      ($self) { $self->{peer} }
sub record    ($self) { +{ map { $_ => $self->{$_} } qw(id transport peer addr hc) } }

sub healthy ($self) { $self->{fails} < MAX_FAILS }

# Latency EWMA weighted by concurrent load.  A backend already serving several
# in-flight requests is penalised so power-of-two choices spread the load.
sub score ($self) {
    my $lat = $self->{ewma} // DEFAULT_EWMA;
    return $lat * ($self->{inflight} + 1);
}

sub begin ($self) {
    $self->{inflight}++;
    return $self;
}

sub done ($self, $latency = undef) {
    $self->{inflight}-- if $self->{inflight} > 0;
    $self->{fails} = 0;
    $self->{served}++;
    if (defined $latency) {
        $self->{ewma} = defined $self->{ewma}
            ? ALPHA * $latency + (1 - ALPHA) * $self->{ewma}
            : $latency;
    }
    return $self;
}

sub fail ($self) {
    $self->{inflight}-- if $self->{inflight} > 0;
    $self->{fails}++;
    return $self;
}

# ── The balancer ────────────────────────────────────────────────────────────

package Amin::Proxy::Backend::Pool;
use v5.38; use warnings; use utf8; use experimental 'signatures';

# Built once from a compiled config: one runtime record per declared backend.
# `pick` chooses among the backend ids a route emitted in its <proxy:backend>
# decisions — the router picks the set, the balancer chooses one (§4.3).
sub new ($class, %o) {
    my $config = $o{config} // die "Backend::Pool needs config =>\n";
    my %rt = map { $_ => Amin::Proxy::Backend->new($config->backend($_)) }
             keys %{ $config->backends };
    return bless {
        runtime => \%rt,
        # Injectable RNG: tests need deterministic picks; production uses rand.
        rand    => $o{rand} // sub { rand },
    }, $class;
}

sub get ($self, $id) { $self->{runtime}{$id} }

# p2c_ewma: sample two distinct candidates, take the lower score.  One
# candidate is returned directly; an all-down set is returned anyway (better a
# likely-failing connect than a hard refusal the router did not authorise).
sub pick ($self, @ids) {
    my @cand = grep { defined } map { $self->{runtime}{$_} } @ids;
    return undef unless @cand;
    return $cand[0] if @cand == 1;

    my $rand = $self->{rand};
    my $n    = @cand;
    my ($i, $j) = (int($rand->() * $n), int($rand->() * $n));
    ($i, $j) = ($j, ($i + 1) % $n) if $i == $j;

    my ($a, $b) = ($cand[$i], $cand[$j]);
    # Prefer a healthy candidate over a down one regardless of score.
    return $a if $a->healthy && !$b->healthy;
    return $b if $b->healthy && !$a->healthy;
    return $a->score <= $b->score ? $a : $b;
}

1;
