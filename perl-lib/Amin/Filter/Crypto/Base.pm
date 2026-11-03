package Amin::Filter::Crypto::Base;

# ═══════════════════════════════════════════════════════════════════════════
# Shared plumbing for the `sec:` (post-quantum E2EE) SAX filters.
#
# The `sec:` namespace is payload-neutral: the same Double Ratchet drives a
# chat message, a UI tree, or any other element stream.  These filters are
# therefore thin, additive SAX stages over the Rust `ratchet` crate, driven
# through `rctool` exactly the way Storage::Bitcache drives `bctool`:
#
#   * one of them (`*Seal`) replaces a plaintext-bearing element with its
#     sealed form,
#   * one of them (`*Open`) replaces a sealed element with the recovered
#     payload carried downstream as <amin:stream>,
#   * every failure is fail-closed — nothing is emitted, the error is logged.
#
# Concrete filters declare the element they own (`_capture_name`) and what to
# do with the captured attributes/text (`_handle`).  All protocol bytes are
# lowercase hex, matching `rctool`'s wire form.
# ═══════════════════════════════════════════════════════════════════════════

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use IPC::Run qw(harness start finish);
use Class::Tiny qw(rctool_path session_path ad Handler Log Mode Name Element),
    { _capturing => 0, _cap_name => '', _cap_attrs => sub { {} }, _buf => '' };

our $SEC_NS  = 'http://projectamin.org/ns/sec/1';
our $AMIN_NS = 'http://projectamin.org/ns/2026/';

sub _sec_ns  ($self) { $SEC_NS }
sub _amin_ns ($self) { $AMIN_NS }

# ── match: this filter's element in the sec: namespace ─────────────────────
sub _is_sec ($self, $el, $name) {
    return 0 unless $el && ref($el) eq 'HASH';
    return (($el->{NamespaceURI} // '') eq $SEC_NS)
        && (($el->{LocalName} // $el->{Name} // '') eq $name);
}

# ── attribute helpers (Clark notation; unnamespaced keys: "{}local") ───────
sub _find_attr ($self, $attrs, $name) {
    return undef unless $attrs && ref($attrs) eq 'HASH';
    my $k = "{}" . $name;
    return $attrs->{$k}{Value} if exists $attrs->{$k};
    for my $kk (keys %$attrs) {
        (my $base = $kk) =~ s/^\{[^}]*\}//;
        next unless $base eq $name;
        return $attrs->{$kk}{Value};
    }
    return undef;
}

sub _set_attr_ns ($self, $attrs, $ns, $name, $value, $prefix = '') {
    my $k    = length($ns) ? "{$ns}$name" : "{}" . $name;
    my $full = length($prefix) ? "$prefix:$name" : $name;
    $attrs->{$k} = {
        Name => $full, LocalName => $name, Prefix => $prefix,
        NamespaceURI => $ns, Value => $value,
    };
    return;
}

sub _set_attr ($self, $attrs, $name, $value) {
    return $self->_set_attr_ns($attrs, '', $name, $value, '');
}

sub _trim ($self, $s) {
    my $t = $s // '';
    $t =~ s/^\s+|\s+$//g;
    return $t;
}

# The secret Double Ratchet state lives in a file `rctool` reads and rewrites
# each seal/open.  It is addressed by the element's `sec:session` when that is
# a plain path, else by the filter's configured session_path.  A
# `bitcache:blake3:…` reference is a CAS pointer — materialising it from the
# Bitcache slab is a later stage, so until then it fails closed.
sub _session_file ($self, $attrs) {
    my $s = $self->_find_attr($attrs, 'session');
    $s = $self->session_path unless defined $s && length $s;
    return '' unless defined $s && length $s;
    if ($s =~ /^bitcache:/) {
        $self->Log && $self->Log->error(
            "[sec] sec:session '$s' is a Bitcache ref; CAS materialisation not wired yet");
        return '';
    }
    return $s;
}

# Associated data bound into the AEAD: per-element `sec:ad`, else the filter's.
sub _ad ($self, $attrs) {
    my $a = $self->_find_attr($attrs, 'ad');
    return $a if defined $a && length $a;
    return $self->ad // '';
}

# ── rctool bridge ─────────────────────────────────────────────────────────
sub _rctool ($self) {
    return $self->rctool_path if defined $self->rctool_path && length $self->rctool_path;
    require Amin::ToolPaths;
    my $t = Amin::ToolPaths::tool_rctool();
    return length $t ? $t : 'rctool';
}

# Run rctool with @$args, feeding $in on stdin.  Returns ($rc, $stdout, $stderr).
sub _rctool_run ($self, $args, $in = '') {
    my $bin = $self->_rctool;
    unless (-x $bin) {
        $self->Log && $self->Log->error("[sec] rctool binary not found at $bin");
        return (127, '', "rctool not found at $bin");
    }
    my ($out, $err) = ('', '');
    my $h = harness [$bin, @$args], \$in, _accum(\$out), _accum(\$err), debug => 0;
    my $ok = eval { start $h; finish $h; 1 };
    my $rc = $? >> 8;
    if (!$ok) {
        my $e = $@ // 'exec failed';
        $self->Log && $self->Log->error("[sec] rctool exec failed: $e");
        return (127, $out, "$e");
    }
    return ($rc, $out, $err);
}

sub _accum ($sv) {
    sub ($data, @) {
        $$sv .= $data if defined $data;
        return ();
    }
}

# Parse rctool's `key\tvalue` TSV stdout into a hashref.
sub _tsv ($self, $text) {
    my %kv;
    for my $ln (split /\n/, $text // '') {
        (my $l = $ln) =~ s/\r$//;
        next unless length $l;
        my ($k, $v) = split /\t/, $l, 2;
        $kv{$k} = $v if defined $v;
    }
    return \%kv;
}

# Carry recovered bytes downstream the way Storage::Bitcache does.
sub _emit_stream ($self, $h, $channel, $data) {
    return unless $h;
    my $attrs = {};
    $self->_set_attr_ns($attrs, $AMIN_NS, 'channel', $channel, 'amin');
    $h->start_element({
        NamespaceURI => $AMIN_NS, LocalName => 'stream',
        Name => 'amin:stream', Prefix => 'amin', Attributes => $attrs,
    });
    $h->characters({ Data => $data });
    $h->end_element({
        NamespaceURI => $AMIN_NS, LocalName => 'stream',
        Name => 'amin:stream', Prefix => 'amin',
    });
    return;
}

# ── capture driver: own element in, _handle(name, attrs, text) out ─────────
# A concrete filter names the sec: element(s) it owns.  _capture_name returns
# the single name; filters that own several (the PQXDH handshake handles both
# the published bundle and the initial message) override _capture_names.
sub _capture_name  ($self) { die ref($self) . " must implement _capture_name" }
sub _capture_names ($self) { ($self->_capture_name) }
sub _handle        ($self, $name, $attrs, $data) { die ref($self) . " must implement _handle" }

# Returns the matched LocalName, or undef if this element is not ours.
sub _owns ($self, $el) {
    my $name = $el->{LocalName} // $el->{Name} // '';
    for my $n ($self->_capture_names) {
        return $name if $self->_is_sec($el, $n);
    }
    return undef;
}

sub start_element ($self, $el) {
    if (my $name = $self->_owns($el)) {
        $self->{_capturing} = 1;
        $self->{_cap_name}  = $name;
        $self->{_cap_attrs} = { %{ $el->{Attributes} // {} } };
        $self->{_buf}       = '';
        return;
    }
    return if $self->{_capturing};
    return $self->SUPER::start_element($el);
}

sub characters ($self, $d) {
    if ($self->{_capturing}) {
        $self->{_buf} .= $d->{Data} // '';
        return;
    }
    return $self->SUPER::characters($d);
}

sub end_element ($self, $el) {
    if ($self->{_capturing} && $self->_is_sec($el, $self->{_cap_name})) {
        $self->{_capturing} = 0;
        my $name  = delete $self->{_cap_name};
        my $data  = delete $self->{_buf};
        my $attrs = delete $self->{_cap_attrs};
        $self->{_buf} = '';
        $self->_handle($name, $attrs, $data);
        return;
    }
    return if $self->{_capturing};
    return $self->SUPER::end_element($el);
}

1;
