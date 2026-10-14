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
        handler             => $opts{Handler},
        log                 => $opts{Log},
        late_filters_enable => $opts{late_filters_enable} // { map => 1, ui => 1 },
        ui_os               => $opts{ui_os}   // 'tty',
        map_out             => $opts{map_out} // 'svg',
        machine_spec        => $opts{machine_spec},
        machine_spec_xml    => $opts{machine_spec_xml},
        machine_spec_path   => $opts{machine_spec_path},
        machine_spec_uri    => $opts{machine_spec_uri},
    }, $class;
    return $self;
}

sub parse ($self, $xml) {
    my $machine = Amin::Machine::Dispatcher->new(
        Mode => $self->{mode},
        late_filters_enable => $self->{late_filters_enable},
        (defined $self->{handler}           ? (Handler => $self->{handler})           : ()),
        (defined $self->{log}               ? (Log     => $self->{log})               : ()),
        (defined $self->{machine_spec}      ? (machine_spec      => $self->{machine_spec})      : ()),
        (defined $self->{machine_spec_xml}  ? (machine_spec_xml  => $self->{machine_spec_xml})  : ()),
        (defined $self->{machine_spec_path} ? (machine_spec_path => $self->{machine_spec_path}) : ()),
        (defined $self->{machine_spec_uri}  ? (bc_uri           => $self->{machine_spec_uri})  : ()),
    );
    XML::LibXML::SAX->new(Handler => $machine)->parse_string($xml);
    my $h = $machine->Handler;
    $h->can('output') && return $h->output;
    return;
}

1;
