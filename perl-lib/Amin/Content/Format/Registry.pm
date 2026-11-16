package Amin::Content::Format::Registry;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';

# Format ids → writer class + MIME type.  Backends are loaded lazily so a
# machine without a given writer still builds the filter chain; the filter
# turns a missing backend into a amin:result error instead of a boot die.

my %MIME = (
    xlsx => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
);

my %ALIAS = (
    excel => 'xlsx',
    xlsm  => 'xlsx',
);

sub canonical ($format) {
    return '' unless defined $format && length $format;
    my $f = lc $format;
    return $ALIAS{$f} // $f;
}

sub mime_for ($format) {
    return $MIME{ canonical($format) } // 'application/octet-stream';
}

sub supported ($format) {
    return exists $MIME{ canonical($format) };
}

sub writer_for ($format, %o) {
    my $f = canonical($format);
    return (undef, "unsupported content format '$format'") unless length $f;
    if ($f eq 'xlsx') {
        my $ok = eval { require Amin::Content::XLSX::Writer; 1 };
        return (undef, 'XLSX backend unavailable') unless $ok;
        return (Amin::Content::XLSX::Writer->new(%o), undef);
    }
    return (undef, "unsupported content format '$format'");
}

1;
