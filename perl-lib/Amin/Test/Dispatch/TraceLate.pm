package Amin::Test::Dispatch::TraceLate;

# Amin::Test::Dispatch::TraceLate — t/19 subtest 2 helper.
# Injects 1 synthetic <amin:late-synth _trace_marker=LATE_INJECTED> after
# every non-synth start_element (so we do an assertion that TraceEnd in
# position=end sees it — proving end runs AFTER late). Tracks
# injected_count for the stress-guard assertion: injected_count == 1.
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Test::Handler';

use Amin qw(NS);
use Class::Tiny { injected_count => 0, ns => sub { NS() } };

sub BUILD ($self, @) {
    $self->label('TraceLate(late-position synthetic injector)');
}

sub start_element ($self, $el) {
    $self->SUPER::start_element($el);
    return if ($el->{LocalName} // '') eq 'late-synth';
    my $ns = $self->ns // NS();
    my $synthetic = {
        NamespaceURI => $ns,
        LocalName    => 'late-synth',
        Name         => 'amin:late-synth',
        Prefix       => 'amin',
        Attributes   => {
            '{}_trace_marker' => {
                Name         => '_trace_marker',
                LocalName    => '_trace_marker',
                Prefix       => '',
                NamespaceURI => '',
                Value        => 'LATE_INJECTED',
            },
        },
    };
    $self->{injected_count}++;
    return $self->SUPER::start_element($synthetic);
}

1;
