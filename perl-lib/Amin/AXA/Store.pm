package Amin::AXA::Store;
use v5.38; use warnings; use utf8;
use Class::Tiny { data => sub { {} } };

# State lives behind Amin::AXA::Store (plan §4.7): get/set/delete keyed by
# session id.  This is the in-memory adapter for the demo — Bitcache or
# SQLite adapters come later behind the same three methods.
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

1;
