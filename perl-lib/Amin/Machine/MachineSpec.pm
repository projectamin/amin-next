package Amin::Machine::MachineSpec;
use v5.38; use warnings; use utf8;
use experimental 'signatures';
use File::Basename qw(dirname);
use Cwd qw(abs_path);
use Encode qw(decode);

sub new ($class, %o) {
    bless { %o }, $class;
}

sub allowed ($self) {
    return $self->{allowed} if exists $self->{allowed};
    $self->{allowed} = $self->spec->{allowed};
    return $self->{allowed};
}

sub spec ($self) {
    return $self->{spec} if exists $self->{spec};
    my $xml = $self->_load;
    $self->{spec} = $self->_parse($xml);
    return $self->{spec};
}

# The signed-reference half (parse → get → verify) lives in
# Amin::Bitcache::Reference so a machine spec, a proxy config and a route spec
# all resolve through one implementation (proxy-plan §5.13).  The spec keeps
# only the disk-candidate half below.
sub _reference ($self) {
    return $self->{_reference} if $self->{_reference};
    require Amin::Bitcache::Reference;
    return $self->{_reference} = Amin::Bitcache::Reference->new(
        uri   => $self->{bc_uri},
        path  => $self->{path},
        hash  => $self->{bc_hash},
        slab_path        => $self->{slab_path},
        bctool_path      => $self->{bctool_path},
        trust_anchor_dir => $self->{trust_anchor_dir},
        signer_name      => $self->{signer_name},
        signer_ts        => $self->{signer_ts},
        signer_vk        => $self->{signer_vk},
        signer_sig       => $self->{signer_sig},
    )->parse;
}

sub _load ($self) {
    if (defined $self->{xml}) {
        return $self->{xml};
    }
    my $ref = $self->_reference;
    if ($ref->addressed) {
        $self->{_from_bitcache} = 1;
        my $bytes = $ref->resolve;
        return undef unless defined $bytes && length $bytes;
        return decode('UTF-8', $bytes);
    }
    # Explicit URI/path form on $self->{path} or $self->{uri}: file://, http(s)://,
    # bitcache/bc:// handled above.  file:// is read as a local file; http(s)://
    # is fetched.  This keeps -u/URI semantics consistent across amin/axa/rust.
    for my $candidate ($self->_uri_candidates) {
        next unless defined $candidate && length $candidate;
        my $bytes = $self->_load_uri($candidate);
        return $bytes if defined $bytes && length $bytes;
    }
    for my $candidate ($self->_candidates) {
        next unless defined $candidate && length $candidate;
        if (-f $candidate) {
            open(my $fh, '<:encoding(UTF-8)', $candidate) or next;
            local $/;
            my $content = <$fh>;
            close $fh;
            return $content if defined $content && length $content;
        }
    }
    return undef;
}

sub _uri_candidates ($self) {
    my @c;
    for my $v ($self->{uri}, $self->{path}) {
        next unless defined $v && length $v;
        push @c, $v if $v =~ m{\A(?:file|https?|bitcache|bc)://}i;
    }
    return @c;
}

# Load bytes from an explicit URI.  file:// reads locally.  http(s):// fetches
# via HTTP::Tiny (core in modern Perl; fail-closed on errors).  bitcache/bc://
# should have been handled by the addressed-reference path; we still accept it
# here for callers that pass it as uri/path without signer params.
sub _load_uri ($self, $uri) { return _load_uri_static($uri) }

# Static/class URI loader so other callers (bin/amin -u, axa, tests) can
# resolve file://, http(s)://, and bitcache/bc:// consistently.
sub _load_uri_static ($uri) {
    return undef unless defined $uri && length $uri;
    if ($uri =~ m{\A(?:bitcache|bc)://}i) {
        my $ref = Amin::Bitcache::Reference->new(uri => $uri)->parse;
        if ($ref->addressed) {
            my $b = $ref->resolve;
            return (defined $b && length $b) ? decode('UTF-8', $b) : undef;
        }
        return undef;
    }
    if ($uri =~ m{\Afile://(?:localhost)?(/.*)\z}i) {
        my $p = $1;
        $p =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
        open my $fh, '<:raw', $p or return undef;
        local $/; my $b = <$fh>; close $fh;
        return defined $b ? decode('UTF-8', $b) : undef;
    }
    if ($uri =~ m{\Ahttps?://}i) {
        my $bytes = eval {
            require HTTP::Tiny;
            my $res = HTTP::Tiny->new(timeout => 20, verify_SSL => 1)->get($uri);
            ($res && $res->{success}) ? $res->{content} : undef;
        };
        return (defined $bytes && length $bytes) ? decode('UTF-8', $bytes) : undef;
    }
    return undef;
}

sub _candidates ($self) {
    my @c;
    for my $v ($self->{path}, $self->{uri}) {
        next unless defined $v && length $v;
        push @c, $v unless $v =~ m{\A(?:file|https?|bitcache|bc)://}i;
    }
    push @c, $ENV{AMIN_MACHINE_SPEC} if $ENV{AMIN_MACHINE_SPEC} && $ENV{AMIN_MACHINE_SPEC} !~ m{\A(?:file|https?|bitcache|bc)://}i;
    push @c, '/etc/amin/machine_spec.xml';
    push @c, ($ENV{HOME} // '') . '/.amin/machine_spec.xml' if $ENV{HOME};
    my $bundled = abs_path(dirname(__FILE__) . '/machine_spec.xml');
    push @c, $bundled if $bundled;
    return @c;
}

sub _parse ($self, $xml) {
    # No spec loaded (e.g. bitcache resolve/verify failed) -> degrade closed:
    # no allowlist, no filters, unnamed. Caller sees an empty contract.
    return {
        filters => [], allowed => {}, filtermap => {},
        handler => undef, log => undef, generator => undef, name => undef,
        ui_dialects => {}, map_dialects => {}, vocab_names => [], vocab => [],
    } unless defined $xml && length $xml;

    # `name` is metadata, not a contract requirement: app specs may be
    # deliberately minimal (a single filter declaration, no machine name).
    return $self->_parse_collect($xml, $self->{_spec_path}, {});
}

# Collect one spec document.  <amin:include> is resolved explicitly at parse
# time (no runtime discovery): path= resolves relative to the including spec,
# spec="amin-core" resolves to the stock Amin machine spec.  Includes are merged
# in document order; later declarations win for name/handler/log/generator and
# dialect targets, while filters/vocab are appended.  $seen prevents cycles.
sub _parse_collect ($self, $xml, $base_path, $seen) {
    my ($ok, $c, $err) = (0, undef, '');
    eval {
        $c = Amin::Machine::MachineSpec::Collector->new;
        require XML::SAX::ParserFactory;
        my $p = XML::SAX::ParserFactory->parser(Handler => $c);
        # Ensure bytes/string form acceptable to parser: encode back to UTF-8 bytes
        # if it contains wide chars, since some SAX parsers choke on upgraded strings.
        my $xml_bytes = $xml;
        if (utf8::is_utf8($xml_bytes)) {
            require Encode;
            $xml_bytes = Encode::encode('UTF-8', $xml_bytes);
        }
        $p->parse_string($xml_bytes);
        $ok = 1;
        1;
    } or do { $err = $@ || 'unknown parse error' };
    die "MachineSpec parse error: $err" unless $ok;

    my $result = {
        filters      => [],
        allowed      => {},
        filtermap    => {},
        handler      => undef,
        log          => undef,
        generator    => undef,
        name         => undef,
        ui_dialects  => {},
        map_dialects => {},
        vocab_names  => [],
    };

    my $base_dir = defined $base_path && length $base_path
        ? do { require File::Basename; File::Basename::dirname($base_path) }
        : undef;

    for my $inc (@{ $c->{includes} // [] }) {
        my $inc_path = $self->_resolve_include($inc, $base_dir);
        my $canon = $self->_canon_path($inc_path);
        die "MachineSpec parse error: include cycle: $inc_path" if $seen->{$canon};
        local $seen->{$canon} = 1;
        my $ixml = $self->_slurp($inc_path);
        my $child = $self->_parse_collect($ixml, $inc_path, $seen);
        $self->_merge_spec($result, $child);
    }

    my $local = {
        filters      => $c->{filters},
        allowed      => $self->_name2spec_from_filters($c->{filters}),
        filtermap    => {},
        handler      => $c->{handler},
        log          => $c->{log},
        generator    => $c->{generator},
        name         => $c->{name},
        ui_dialects  => $c->{ui_dialects},
        map_dialects => $c->{map_dialects},
        vocab_names  => $c->{vocab_names} // [],
    };
    $self->_merge_spec($result, $local);
    $result->{allowed} = $self->_name2spec_from_filters($result->{filters});
    # Back-compat alias: BSAX callers harvest the band from `vocab`.
    $result->{vocab} = $result->{vocab_names};
    return $result;
}

sub _merge_spec ($self, $dst, $src) {
    push @{ $dst->{filters} }, @{ $src->{filters} // [] };
    push @{ $dst->{vocab_names} }, @{ $src->{vocab_names} // [] };
    $dst->{ui_dialects}  = { %{ $dst->{ui_dialects}  // {} }, %{ $src->{ui_dialects}  // {} } };
    $dst->{map_dialects} = { %{ $dst->{map_dialects} // {} }, %{ $src->{map_dialects} // {} } };
    for my $k (qw(handler log generator name)) {
        $dst->{$k} = $src->{$k} if defined $src->{$k};
    }
    return $dst;
}

sub _name2spec_from_filters ($self, $filters) {
    my %allowed;
    for my $f (@{ $filters // [] }) {
        my $class = $f->{class} // next;
        $allowed{$class} = $f->{meta} // {};
    }
    return \%allowed;
}

sub _resolve_include ($self, $inc, $base_dir) {
    my $spec = $inc->{spec} // '';
    if ($spec eq 'amin-core') {
        require File::Basename;
        require Cwd;
        my $here = File::Basename::dirname(Cwd::abs_path(__FILE__));
        return "$here/machine_spec.xml";
    }
    my $path = $inc->{path} // $inc->{file} // $inc->{src} // '';
    die "MachineSpec parse error: <amin:include> requires path=... or spec=\"amin-core\"\n"
        unless length $path;
    die "MachineSpec parse error: include path must be local\n"
        if $path =~ m{\A[A-Za-z][A-Za-z0-9+.-]*://} && $path !~ m{\Afile://}i;
    if ($path =~ m{\Afile://(?:localhost)?(/.*)\z}i) {
        $path = $1;
        $path =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
    }
    if ($path !~ m{\A/} && defined $base_dir) {
        $path = "$base_dir/$path";
    }
    require Cwd;
    my $abs = Cwd::abs_path($path);
    die "MachineSpec parse error: include not found: $path\n" unless defined $abs && -f $abs;
    return $abs;
}

sub _canon_path ($self, $path) {
    require Cwd;
    return Cwd::abs_path($path) // $path;
}

sub _slurp ($self, $path) {
    open my $fh, '<:raw', $path or die "MachineSpec parse error: cannot read $path: $!\n";
    local $/;
    my $b = <$fh>;
    close $fh;
    return defined $b ? decode('UTF-8', $b) : $b;
}

sub _allow_all_registered ($self) {
    require Amin::Machine::Dispatcher;
    my %allowed;
    for my $pos (keys %Amin::Machine::Dispatcher::FILTERS) {
        for my $f ($Amin::Machine::Dispatcher::FILTERS{$pos}->@*) {
            $allowed{$f->{class}} = 1;
        }
    }
    return \%allowed;
}

# A SAX2 collector for the machine spec itself.  The spec is XML, so it is read
# with the same generator a profile is — never a DOM.  It fills the
# {filters, ui_dialects, handler, log, generator, name} slots the XPath pass
# produced, keeping the `class`/`name` attribute out of each filter's meta
# (the class is the source of truth for a filter's verb).
package Amin::Machine::MachineSpec::Collector;
use v5.38; use warnings;

sub new ($class) {
    bless {
        filters => [], ui_dialects => {}, map_dialects => {}, name => undef,
        includes => [],
        _in_name => 0, _name_text => '',
        # BSAX dynamic vocabulary band: LocalNames the spec declares in document
        # order — every element-scoped `<filter element=…>` plus any explicit
        # `<vocab><name>…</name></vocab>`.  Raw (unfiltered) here; the codec
        # drops core names and assigns band NAME_IDs (ESCAPE+1, …) itself.
        vocab_names => [],
        _in_vocab => 0, _capturing_vname => 0, _vname_text => '',
    }, $class;
}

# SAX attribute surfaces vary in key shape ({Name} / {ns}Name); normalise to
# LocalName => Value, which is all the spec ever reads.
sub _surface ($el) {
    my %a;
    for my $k (keys %{ $el->{Attributes} // {} }) {
        my $h = $el->{Attributes}{$k} // {};
        my $n = $h->{LocalName} // $h->{Name} // $k;
        $a{$n} = $h->{Value};
    }
    return %a;
}

sub start_document ($self, @) { return }
sub end_document   ($self, @) { return }
sub characters ($self, $ch) {
    my $d = $ch->{Data};
    $self->{_name_text}  .= $d if $self->{_in_name}        && defined $d;
    $self->{_vname_text} .= $d if $self->{_capturing_vname} && defined $d;
    return;
}

sub start_element ($self, $el) {
    my $name = $el->{LocalName} // $el->{Name} // '';
    return unless length $name;
    my %a = _surface($el);
    # Inside <vocab>, only <name> children matter: each contributes one
    # spec-declared LocalName to the BSAX dynamic vocabulary band.  Returning
    # early stops <vocab><name> being mistaken for the machine <name>.
    if ($self->{_in_vocab}) {
        if ($name eq 'name') { $self->{_capturing_vname} = 1; $self->{_vname_text} = '' }
        return;
    }
    if ($name eq 'vocab') { $self->{_in_vocab} = 1; return }
    if ($name eq 'filter') {
        my $class = $a{class} // $a{name};
        return unless defined $class && length $class;
        my %meta = %a;
        delete @meta{qw(class name)};
        push $self->{filters}->@*, { class => $class, meta => \%meta };
        # An element-scoped filter declares a LocalName the machine's BSAX
        # vocabulary must cover — harvested in document order (first-seen wins).
        push @{ $self->{vocab_names} }, $a{element}
            if defined $a{element} && length $a{element};
    }
    elsif ($name eq 'ui-dialect' || $name eq 'map-dialect') {
        my ($t, $c) = ($a{target}, $a{class} // $a{name});
        if (defined $t && length $t && defined $c && length $c) {
            my $key = $name eq 'ui-dialect' ? 'ui_dialects' : 'map_dialects';
            $self->{$key}{$t} = { class => $c };
        }
    }
    elsif ($name eq 'include') {
        my %inc = %a;
        push @{ $self->{includes} }, \%inc if %inc;
    }
    elsif (($name eq 'handler' || $name eq 'log' || $name eq 'generator')
           && !defined $self->{$name}) {
        my $class = $a{class} // $a{name};
        if (defined $class && length $class) {
            my %attrs = %a;
            delete @attrs{qw(class name)};
            $self->{$name} = { class => $class, attrs => \%attrs };
        }
    }
    elsif ($name eq 'name' && !defined $self->{name}) {
        $self->{_in_name} = 1;
        $self->{_name_text} = '';
    }
    return;
}

sub end_element ($self, $el) {
    my $name = $el->{LocalName} // $el->{Name} // '';
    if ($self->{_capturing_vname} && $name eq 'name') {
        $self->{_capturing_vname} = 0;
        (my $t = $self->{_vname_text}) =~ s/^\s+|\s+$//g;
        push $self->{vocab_names}->@*, $t if length $t;
        return;
    }
    if ($name eq 'vocab') { $self->{_in_vocab} = 0; return }
    if ($name eq 'name' && $self->{_in_name}) {
        $self->{_in_name} = 0;
        (my $t = $self->{_name_text}) =~ s/^\s+|\s+$//g;
        $self->{name} = $t if length $t;
    }
    return;
}

package Amin::Machine::MachineSpec;

1;
