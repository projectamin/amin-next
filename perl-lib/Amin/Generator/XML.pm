package Amin::Generator::XML;
use v5.38; use warnings; use utf8;
use Encode ();

# The XML half of the SAX generator pair — the other is Amin::Generator::BSAX.
# A profile may arrive as XML, and *which* XML SAX driver turns those bytes
# into events is a property of the machine, never of the profile:
#
#   XML::LibXML::SAX    the fast path — XS over libxml2; a dev host has it
#   XML::SAX::PurePerl  the portable path — pure Perl, so a cross-built node
#                       that carries no C XML library still reads a profile
#
# Both are SAX2 drivers, so the event stream a Handler sees is the same; the
# driver only decides how fast the bytes become events.  Keeping the choice
# here (not in Amin.pm, not in the machine spec) is what lets one Perl runtime
# read a profile on a laptop and on a phone with no C XML stack between them.

our @DRIVERS = qw(XML::LibXML::SAX XML::SAX::PurePerl);

# The first driver this machine actually has.  Called per parse: a node that
# gains libxml2 later starts using it with no config change.
sub driver_class () {
    for my $class (@DRIVERS) {
        (my $file = "$class.pm") =~ s{::}{/}g;
        return $class if eval { require $file; 1 };
    }
    die "Amin: no XML SAX driver is installed (looked for @DRIVERS)\n";
}

# The same constructor + parse_string surface Amin::Generator::BSAX exposes, so
# a machine spec's <generator class="…"/> may name either generator by name.
sub new ($class, %o) { bless { %o }, $class }

sub parse_string ($self, $xml) {
    my $handler = $self->{Handler} or return;
    my $driver = driver_class();
    # PurePerl decodes the string itself — it takes bytes and honours the
    # XML declaration's encoding.  A caller that read a file through an
    # :encoding(UTF-8) layer holds characters instead, so re-encode for it.
    # LibXML takes the characters as-is.  A byte string (the BSAX '<' fallback)
    # needs no conversion for either driver.
    $xml = Encode::encode('UTF-8', $xml)
        if $driver ne 'XML::LibXML::SAX' && utf8::is_utf8($xml);
    $driver->new(Handler => $handler)->parse_string($xml);
    return;
}

1;
