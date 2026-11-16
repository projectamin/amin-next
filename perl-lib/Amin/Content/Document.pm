package Amin::Content::Document;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Content';

use Amin::Content::Format::Registry;

use constant RC_CONTENT_FORMAT => -6201;
use constant RC_CONTENT_DENIED => -6202;
use constant RC_CONTENT_IO     => -6203;
use constant RC_CONTENT_BUILD  => -6204;

# ═══════════════════════════════════════════════════════════════════════════
# Amin::Content::Document — late filter for <amin:document>.
#
# The document grammar ships as part of the Amin platform, so it lives in the
# core `amin:` namespace: an application (or a Rust filter) can claim its own
# namespace URI for its own document grammar without colliding with ours.
#
# The filter owns one document element at a time.  It feeds the grammar into a
# format writer (chosen by Amin::Content::Format::Registry) and, when the
# element closes, builds the artifact, stores it in the CAS and emits one
# amin:result plus one compact bc:object ref.
#
# Why `late`: Storage::Bitcache sits in `middle`, so a document built in the
# middle region would be fetched back and re-inlined by the time it reached
# the output handler.  The late region is downstream of that boundary.
#
#   <amin:document format="xlsx" out="report.xlsx" root="/var/lib/amin">
#     <amin:style id="hdr" bold="1" fill="#DDEEFF"/>
#     <amin:sheet name="Report">
#       <amin:row r="1">
#         <amin:cell type="string" style="hdr">Name</amin:cell>
#       </amin:row>
#     </amin:sheet>
#   </amin:document>
#
# Render/prod/dryrun stay side-effect free: `out` is echoed on bc:object but
# no file is touched.  Only Mode=run writes, and only under amin:root, and
# only when a zcap scope was established by the begin-region Auth::ZCap filter.
# ═══════════════════════════════════════════════════════════════════════════

sub name     { '' }
sub element  { 'document' }
sub position { 'late' }

sub start_element ($self, $el) {
    my $ln = $el->{LocalName} // '';
    if (Amin::Content::_is_content($el)) {
        if (!$self->{_doc} && $ln eq $self->_element_name) {
            $self->_open_document($el);
        }
        elsif ($self->{_writer} && $self->{_doc}) {
            # An amin:document nested inside this one is just an unknown
            # child to the writer; remember it so its close does not end the
            # outer document.
            $self->{_nested_doc}++ if $ln eq $self->_element_name;
            $self->{_writer}->handle_start($ln, { $self->_attrs($el) });
            if ($self->{_writer}->is_text_element($ln)) {
                $self->{_text_ln} = $ln;
                $self->{_text}    = '';
            }
        }
    }
    return $self->SUPER::start_element($el);
}

sub characters ($self, $d) {
    $self->{_text} .= $d->{Data} // ''
        if defined $self->{_text_ln} && $self->{_doc};
    return $self->SUPER::characters($d);
}

sub end_element ($self, $el) {
    my $ln = $el->{LocalName} // '';
    if (Amin::Content::_is_content($el) && $self->{_doc}) {
        if ($self->{_writer}) {
            if (defined $self->{_text_ln} && $self->{_text_ln} eq $ln) {
                $self->{_writer}->handle_text($ln, $self->{_text}, {});
                $self->{_text_ln} = undef;
                $self->{_text}    = '';
            }
            $self->{_writer}->handle_end($ln);
        }
        if ($ln eq $self->_element_name) {
            if ($self->{_nested_doc}) {
                $self->{_nested_doc}--;
            } else {
                $self->_close_document;
            }
        }
    }
    return $self->SUPER::end_element($el);
}

sub _open_document ($self, $el) {
    my %a = $self->_attrs($el);
    my $format = $a{format} // '';
    $format = _infer_format($a{out}) unless length $format;
    $format = 'xlsx' unless length $format;

    $self->{_attrs}   = \%a;

    my ($writer, $err) = Amin::Content::Format::Registry::writer_for($format,
        title       => $a{title},
        author      => $a{author},
        subject     => $a{subject},
        keywords    => $a{keywords},
        description => $a{description});

    if (!$writer) {
        $self->_emit_error(RC_CONTENT_FORMAT, 'content_format', $err, $format);
        return;
    }

    my $canonical = Amin::Content::Format::Registry::canonical($format);
    $writer->start_document(\%a);
    $self->{_doc}    = { format => $canonical, writer => $writer };
    $self->{_writer} = $writer;
    return;
}

sub _close_document ($self) {
    my $doc = $self->{_doc};
    my $writer = $self->{_writer};
    $self->{_doc} = undef;
    $self->{_writer} = undef;
    delete $self->{_text_ln};
    delete $self->{_text};

    my $format = $doc->{format} // 'xlsx';
    my ($bytes, $err) = $writer ? $writer->finish : (undef, 'no writer');
    return $self->_emit_error(RC_CONTENT_BUILD, 'content_build', $err, $format)
        unless defined $bytes;

    my $a    = $self->{_attrs} // {};
    my $out  = $a->{out};
    my $root = $a->{root};

    my $path;
    if (defined $out && length $out) {
        if (($self->Mode // 'render') eq 'run') {
            my ($resolved, $perr) = _confine_path($out, $root);
            return $self->_emit_error(RC_CONTENT_DENIED, 'content_path', $perr, $format)
                unless defined $resolved;

            my $scope = eval {
                require Amin::Auth::ZCap;
                Amin::Auth::ZCap->current_scope_attrs;
            };
            return $self->_emit_error(RC_CONTENT_DENIED, 'content_denied',
                'run-mode amin:out write requires a zcap scope', $format)
                unless $scope;

            my $werr = _write_bytes($resolved, $bytes);
            return $self->_emit_error(RC_CONTENT_IO, 'content_io', $werr, $format)
                if $werr;
            $self->Log && $self->Log->info(
                "[content/out] $resolved <- " . length($bytes) . " bytes");
        }
        $path = $out;
    }

    my ($hash, $size) = $self->_bc_put(\$bytes);
    return $self->_emit_error(RC_CONTENT_BUILD, 'content_build',
        'failed to store the artifact', $format)
        unless defined $hash;

    my $mime = Amin::Content::Format::Registry::mime_for($format);
    my %stats = (
        sheets => $writer->sheet_count,
        rows   => $writer->stats->{rows}  // 0,
        cells  => $writer->stats->{cells} // 0,
    );

    $self->_emit_result(
        kind   => 'document',
        format => $format,
        mime   => $mime,
        hash   => $hash,
        size   => $size,
        %stats,
    );

    my %obj = (
        hash   => $hash,
        size   => $size,
        kind   => 'document',
        mime   => $mime,
        format => $format,
        %stats,
    );
    $obj{path} = $path if defined $path && length $path;
    $self->_emit_bc_object(%obj);
    return;
}

sub _emit_error ($self, $rc, $exit_kind, $msg, $format) {
    $msg = 'unsupported content format' unless defined $msg && length $msg;
    $self->Log && $self->Log->error("[content] $msg");
    $self->_emit_result(
        kind      => 'error',
        rc        => $rc,
        exit_kind => $exit_kind,
        msg       => $msg,
        format    => $format,
    );
    return;
}

# LocalName → Value for one SAX element.  Namespace declarations and non-hash
# attribute entries are skipped; the writer only reads the grammar's names.
sub _attrs ($self, $el) {
    my %a;
    for my $k (keys %{ $el->{Attributes} // {} }) {
        my $v = $el->{Attributes}{$k};
        next unless ref $v eq 'HASH';
        next if ($v->{Prefix} // '') eq 'xmlns';
        next if ($v->{Name} // '') =~ /^xmlns(?::|$)/;
        my $ln = $v->{LocalName};
        if (!defined $ln || !length $ln) {
            ($ln = $k) =~ s/^\{[^}]*\}//;
        }
        $a{$ln} = $v->{Value};
    }
    return %a;
}

sub _infer_format ($out) {
    return '' unless defined $out && $out =~ /\.([A-Za-z0-9]+)\z/;
    return $1;
}

# Resolve amin:out against amin:root and prove the result stays inside
# it before anything touches the filesystem.  Canonpath is not enough: it keeps
# `..` segments on Unix, so dot segments are collapsed here, and the nearest
# existing ancestor is realpath'ed so a symlink inside the root cannot redirect
# the write out of it.
sub _confine_path ($out, $root) {
    return (undef, 'amin:out is empty') unless defined $out && length $out;
    return (undef, 'amin:out contains a NUL byte') if $out =~ /\0/;
    require File::Spec;
    require File::Basename;
    require Cwd;

    my $base = defined $root && length $root ? $root : '.';
    $base = _collapse(File::Spec->rel2abs($base));
    return (undef, "amin:root '$base' does not exist") unless -d $base;
    my $base_real = Cwd::realpath($base) // $base;

    my $target = File::Spec->file_name_is_absolute($out)
        ? _collapse($out)
        : _collapse(File::Spec->catfile($base_real, $out));

    return (undef, "amin:out '$out' escapes amin:root '$base_real'")
        unless $target ne $base_real && index($target, "$base_real/") == 0;

    if (-e $target || -l $target) {
        my $real = Cwd::realpath($target);
        return (undef, "amin:out '$out' resolves outside amin:root")
            unless defined $real && index($real, "$base_real/") == 0;
        return (undef, "amin:out '$out' is not a regular file")
            unless -f $real;
        return ($real, undef);
    }

    # Target does not exist yet: the closest existing parent must still resolve
    # under the root.  This is the case a symlinked subdirectory would abuse.
    my $dir = File::Basename::dirname($target);
    while (!-d $dir) {
        my $up = File::Basename::dirname($dir);
        last if $up eq $dir;
        $dir = $up;
    }
    if (-d $dir) {
        my $real = Cwd::realpath($dir);
        return (undef, "amin:out '$out' resolves outside amin:root")
            unless defined $real
                && ($real eq $base_real || index($real, "$base_real/") == 0);
    }
    return ($target, undef);
}

# Lexical dot-segment collapse for an absolute path (canonpath leaves `..`).
sub _collapse ($path) {
    require File::Spec;
    my @keep;
    for my $seg (File::Spec->splitdir($path)) {
        next if $seg eq '' || $seg eq File::Spec->curdir;
        if ($seg eq File::Spec->updir) {
            pop @keep if @keep;
            next;
        }
        push @keep, $seg;
    }
    my $root = File::Spec->rootdir;
    return File::Spec->catdir($root, @keep);
}

# Caller has already established a zcap scope and a confined path.
sub _write_bytes ($path, $bytes) {
    require File::Basename;
    require File::Path;
    my $dir = File::Basename::dirname($path);
    if (!-d $dir) {
        eval { File::Path::make_path($dir) };
        return "cannot create $dir: $@" unless -d $dir;
    }
    open(my $fh, '>:raw', $path) or return "cannot write $path: $!";
    print {$fh} $bytes or do { close $fh; return "cannot write $path: $!" };
    close $fh or return "cannot write $path: $!";
    return undef;
}

1;
