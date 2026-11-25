package Amin::UI::Target::HTML::Visualizer;

# Client half of ui:visualizer.  The target owns the look: an app names a
# curated mode and the target ships the shader, so no app-supplied GLSL (or any
# other script) crosses the trust boundary.  The shader is carried as base64
# inside a non-executable <script> payload, decoded at run time — GLSL has no
# '<' guarantee, and the page must stay XML-safe.
#
# The runtime is a shared file because the Rust target embeds the same bytes
# (include_str!): the page is the Perl/Rust parity contract.  Both assets are
# read at load, not per render.

use v5.38; use warnings; use utf8;
use experimental 'signatures';
use Carp qw(croak);
use File::Spec;
use File::Basename qw(dirname);

sub _read ($rel) {
    my $path = File::Spec->catfile(dirname(__FILE__), split m{/}, $rel);
    open my $fh, '<:raw', $path or croak "visualizer asset missing: $path ($!)";
    local $/;
    my $text = <$fh>;
    close $fh;
    return $text;
}

our $RUNTIME = _read('runtimes/visualizer.js');
our $SHADER  = _read('shaders/visualizer.glsl.b64');

1;
