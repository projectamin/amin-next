package Amin;
use v5.38; use warnings; use utf8; use parent 'Exporter';

use constant NS      => 'http://projectamin.org/ns/2026/';
use constant VERSION => '3.0.0-bootstrap';

our @EXPORT_OK   = qw(NS VERSION);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

require Amin::Machine::Dispatcher;
require Amin::Handler::Writer;
require Amin::Log::Standard;
require Amin::Generator::XML;
require Amin::Generator::BSAX;

sub new ($class, %opts) {
    my $self = bless {
        mode                => $opts{Mode}    // 'render',
        handler             => $opts{Handler},
        log                 => $opts{Log},
        late_filters_enable => $opts{late_filters_enable} // { map => 1, ui => 1 },
        ui_os               => $opts{ui_os}   // 'tty',
        map_out             => $opts{map_out} // 'xml',
        machine_spec        => $opts{machine_spec},
        machine_spec_xml    => $opts{machine_spec_xml},
        machine_spec_path   => $opts{machine_spec_path},
        machine_spec_uri    => $opts{machine_spec_uri},
    }, $class;
    return $self;
}

# The document is either XML or BSAX, and the CALLER hands it over as BYTES:
# BSAX's magic and length fields are byte offsets, so an encoding layer applied
# before the dialect is known would corrupt it.  Both dialects drive the same
# SAX chain, so the dialect is sniffed rather than configured — XML opens with
# optional whitespace then '<', BSAX with the AMINBSA1 magic
# (Amin::Generator::BSAX::parse_bytes falls back to XML on '<' by itself, so
# either generator can take either document).
sub parse ($self, $doc) {
    my $machine = Amin::Machine::Dispatcher->new(
        Mode => $self->{mode},
        late_filters_enable => $self->{late_filters_enable},
        ui_os   => $self->{ui_os},
        map_out => $self->{map_out},
        (defined $self->{handler}           ? (Handler => $self->{handler})           : ()),
        (defined $self->{log}               ? (Log     => $self->{log})               : ()),
        (defined $self->{machine_spec}      ? (machine_spec      => $self->{machine_spec})      : ()),
        (defined $self->{machine_spec_xml}  ? (machine_spec_xml  => $self->{machine_spec_xml})  : ()),
        (defined $self->{machine_spec_path} ? (machine_spec_path => $self->{machine_spec_path}) : ()),
        (defined $self->{machine_spec_uri}  ? (bc_uri           => $self->{machine_spec_uri})  : ()),
    );
    if (!ref($doc) && substr($doc, 0, 64) =~ /\A\s*</) {
        # XML → characters, so the SAX driver sees the document's declared
        # encoding rather than re-reading the UTF-8 bytes as latin1.
        utf8::decode($doc) unless utf8::is_utf8($doc);
        Amin::Generator::XML->new(Handler => $machine)->parse_string($doc);
    } else {
        # The spec that the Dispatcher just resolved also declares the BSAX
        # vocabulary band, so the decoder resolves spec-declared NAME_IDs with
        # no name wired into Amin core (Configuration as Contract).
        Amin::Generator::BSAX->new(Handler => $machine, vocab => $machine->vocab)
            ->parse_bytes($doc);
    }
    my $h = $machine->Handler;
    $h->can('output') && return $h->output;
    return;
}

1;
