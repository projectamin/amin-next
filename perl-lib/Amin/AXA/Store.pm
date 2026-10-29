package Amin::AXA::Store;
use v5.38; use warnings; use utf8;
use Class::Tiny { data => sub { {} } };

# State lives behind Amin::AXA::Store (plan §4.7): get/set/delete keyed by
# session id, plus update() for a read-modify-write that must not be lost
# when two callers interleave.  This is the in-memory adapter.  SQLite
# (Amin::AXA::Store::SQLite) implements the same methods; its update() holds
# a write transaction so a prefork worker pool cannot clobber a cart.
#
# The store is process-scoped BY DESIGN: it is server-side state that must
# outlive a request (that is the point of a persistent server), which makes
# it the one piece of mutable state §4.9 lists as safe to keep at process
# lifetime only because it is *keyed by session* and never shared across
# sessions.  Records are plain hashrefs: { csrf => ..., cart => { sku => qty } }.

my $DEFAULT;

sub set_default ($class, $store) { $DEFAULT = $store; return $DEFAULT }
sub default ($class) { $DEFAULT //= $class->new }

sub get ($self, $key) { $self->{data}{$key} }
sub set ($self, $key, $value) { $self->{data}{$key} = $value; return $value }
sub delete ($self, $key) { delete $self->{data}{$key}; return }
sub session_ids ($self) { keys $self->{data}->%* }

# One process, so the callback itself is the critical section.  The return
# value is what gets stored; undef leaves the existing record alone and does
# not create a key.  SQLite's update() is the one that has to be atomic
# across processes — this adapter is never shared that way.
sub update ($self, $key, $code) {
    die "axa: store key required\n" unless defined $key && length $key;
    my $next = $code->($self->{data}{$key});
    return $self->{data}{$key} unless defined $next;
    $self->{data}{$key} = $next;
    return $next;
}

1;
