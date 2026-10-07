package Amin::Machine::Dispatcher;
use v5.38; use warnings; use utf8;
use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(Handler Log Mode), { chain => undef };

our %FILTERS;

sub register ($pkg, $class, %meta) {
    my $pos = delete($meta{position}) // 'middle';
    push $FILTERS{$pos}->@*, { class => $class, meta => \%meta };
}

BEGIN {
    require Amin::Command::Mkdir;   __PACKAGE__->register('Amin::Command::Mkdir',
        element => 'command', namespace => NS(), name => 'mkdir',   position => 'middle');
    require Amin::Command::Echo;    __PACKAGE__->register('Amin::Command::Echo',
        element => 'command', namespace => NS(), name => 'echo',    position => 'middle');
    require Amin::Command::Remove;  __PACKAGE__->register('Amin::Command::Remove',
        element => 'command', namespace => NS(), name => 'remove',  position => 'middle');
    require Amin::Cond::OS;         __PACKAGE__->register('Amin::Cond::OS',
        element => undef,   namespace => NS(),                        position => 'begin');
    require Amin::Filter::Map::Topology;
    __PACKAGE__->register('Amin::Filter::Map::Topology',
        element => undef,   namespace => 'http://projectamin.org/ns/map/1',
        namespaces => [NS(), 'http://projectamin.org/ns/map/1'],
        position => 'late');
    require Amin::Filter::UI::SwiftUIView;
    __PACKAGE__->register('Amin::Filter::UI::SwiftUIView',
        element => undef,   namespace => 'http://projectamin.org/ns/ui/1',
        namespaces => [NS(), 'http://projectamin.org/ns/ui/1'],
        position => 'late');
}

sub new ($class, %o) {
    my $self = bless { %o }, $class;
    $self->{chain} = _build_chain($self->Handler, $self->Log, $self->Mode // 'render',
        $self->{late_filters_enable} // { map => 1, ui => 1 });
    return $self;
}

for my $m (qw(start_document end_document
              start_element end_element characters
              processing_command comment ignorable_whitespace)) {
    no strict 'refs';
    *$m = sub ($self, @args) { $self->{chain}->$m(@args) };
}

sub _build_chain ($h, $l, $mode, $late_enable = {}) {
    my $head = $h;
    for my $pos (qw(end permanent late middle begin)) {
        my $filters = $FILTERS{$pos} // [];
        for my $f (reverse @$filters) {
            next if $pos eq 'late' && !$late_enable->{
                $f->{class} =~ /::Map::/    ? 'map'
              : $f->{class} =~ /::UI::/     ? 'ui'  : 1 };
            $head = $f->{class}->new(
                Handler => $head, Log => $l, Mode => $mode,
                Name    => $f->{meta}{name},
                Element => $f->{meta}{element});
            $head->can('name')    && $head->name($f->{meta}{name});
            $head->can('element') && $head->element($f->{meta}{element});
        }
    }
    return $head;
}

1;
