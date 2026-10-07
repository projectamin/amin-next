package Amin;
use v5.38; use warnings; use utf8; use parent 'Exporter';

use constant NS      => 'http://projectamin.org/ns/2026/';
use constant VERSION => '3.0.0-bootstrap';

our @EXPORT_OK   = qw(NS VERSION);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

require Amin::Machine::Dispatcher;
require Amin::Handler::Writer;
require Amin::Log::Standard;
require XML::LibXML::SAX;

sub new ($class, %opts) {
    my $self = bless {
        mode                => $opts{Mode}    // 'render',
        handler             => $opts{Handler} // Amin::Handler::Writer->new,
        log                 => $opts{Log}     // Amin::Log::Standard->new,
        late_filters_enable => $opts{late_filters_enable} // { map => 1, ui => 1 },
        ui_os               => $opts{ui_os}   // 'tty',
        map_out             => $opts{map_out} // 'svg',
    }, $class;
    return $self;
}

sub parse ($self, $xml) {
    my $machine = Amin::Machine::Dispatcher->new(
        Handler => $self->{handler}, Log => $self->{log}, Mode => $self->{mode},
        late_filters_enable => $self->{late_filters_enable},
    );
    XML::LibXML::SAX->new(Handler => $machine)->parse_string($xml);
    $self->{handler}->can('output') && return $self->{handler}->output;
    return;
}

1;
