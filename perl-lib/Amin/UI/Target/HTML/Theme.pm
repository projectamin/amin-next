package Amin::UI::Target::HTML::Theme;
use v5.38; use warnings; use utf8;
use experimental 'signatures';
use File::Spec;
use File::Basename qw(dirname);

# The HTML target's looks, one file each, selected by ui:app theme=.
#
# A theme is data, not code: every sheet is :where()-only (zero specificity),
# so an app's ui:style still wins, and the target emits exactly one <style> per
# page.  The Rust target embeds the same files with include_str!, so adding a
# theme here is a file for Perl and one match arm there — the pages it produces
# stay byte-identical.

our $DEFAULT = 'material';

my %CSS;

sub dir { File::Spec->catdir(dirname(__FILE__), 'themes') }

# The names on disk, for callers that want to offer a picker.
sub names ($class) {
    opendir(my $dh, dir()) or return ($DEFAULT);
    my @n = sort map { /\A([a-z0-9][a-z0-9-]*)\.css\z/ ? $1 : () } readdir $dh;
    closedir $dh;
    return @n ? @n : ($DEFAULT);
}

# Unknown or absent names fall back to the default look: a theme is an
# intent, never a failure mode.
sub css ($class, $name = '') {
    my $n = defined $name && $name =~ /\A[a-z0-9][a-z0-9-]{0,31}\z/ ? $name : $DEFAULT;
    return $CSS{$n} //= _read($n) // ($n eq $DEFAULT ? '' : $class->css($DEFAULT));
}

sub _read ($n) {
    open my $fh, '<:raw', File::Spec->catfile(dir(), "$n.css") or return undef;
    local $/;
    my $s = <$fh>;
    close $fh;
    return $s;
}

1;
