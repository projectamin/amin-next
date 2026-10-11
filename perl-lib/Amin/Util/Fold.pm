package Amin::Util::Fold;
use v5.38; use warnings; use utf8;
use parent 'Exporter';

our @EXPORT_OK   = qw(_vals _flags);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

sub _vals ($params, $key) {
    map { ref eq 'HASH' ? ($_->{$key} // ()) : $_ } @$params;
}

sub _flags ($allowed_names, $flags) {
    my %ok = map {; $_ => 1, length($_) == 1 ? () : (substr($_,0,1) => 1) } @$allowed_names;
    my (@short_bool, @short_val, @long);
    for my $f (@$flags) {
        if (ref $f eq 'HASH') {
            while (my ($k, $v) = each %$f) {
                next unless $ok{$k};
                if (length($k) == 1) {
                    if (defined $v && length($v)) { push @short_val, "-$k$v" }
                    else                          { push @short_bool, $k }
                } else {
                    push @long, (defined $v && length($v) ? "--$k=$v" : "--$k");
                }
            }
        } else {
            next unless $ok{$f};
            if (length($f) == 1) { push @short_bool, $f }
            else                 { push @long,  "--$f" }
        }
    }
    (@short_bool ? '-' . join('', @short_bool) : (), @short_val, @long);
}

1;
