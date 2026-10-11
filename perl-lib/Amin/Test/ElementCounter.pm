package Amin::Test::ElementCounter;

# Amin::Test::ElementCounter — first-class reusable test filter.
#
# Counts element start_element events for a given (ns, ln) tuple and
# asserts against expected_count at end_document.  Drop-in replacement
# for the 5-line inline "push @SeenEvents; is scalar @SeenEvents, N"
# pattern scattered through t/*.t.
#
# Usage from a .t file:
#
#   my $t = Amin::Test::ElementCounter->new(
#       namespace       => NS_CUSTOM,
#       local_name      => 'policy',
#       expected_count  => 3,
#       label           => '3 custom <sox:policy> elements reach middle chain',
#   );
#   Amin::Machine::Dispatcher->run(source_xml => $xml,
#                                   Handler => $writer,
#                                   extra_filters_permanent => [$t]);
#   $t->report;
#
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Test::Handler';

use Class::Tiny qw(namespace local_name expected_count);

sub BUILD ($self, @) {
    $self->label("ElementCounter["
                 . ($self->local_name // '(any)')
                 . '@' . ($self->namespace // '(default)') . ']');
}

sub end_document ($self, @) {
    my $ns = $self->namespace;
    my $ln = $self->local_name;
    my $want = $self->expected_count // 1;
    my %match = ( kind => 'start' );
    $match{ns} = $ns if defined $ns && length $ns;
    $match{ln} = $ln if defined $ln && length $ln;
    $match{count} = $want;
    $self->assert_seen_count(
        $self->label // 'ElementCounter expected count',
        %match);
    return $self->SUPER::end_document({});
}

1;
