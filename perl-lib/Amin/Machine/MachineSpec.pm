package Amin::Machine::MachineSpec;
use v5.38; use warnings; use utf8;
use experimental 'signatures';
use File::Basename qw(dirname);
use Cwd qw(abs_path);

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
        return $bytes;
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

sub _candidates ($self) {
    my @c;
    push @c, $self->{path} if $self->{path};
    push @c, $ENV{AMIN_MACHINE_SPEC} if $ENV{AMIN_MACHINE_SPEC};
    push @c, '/etc/amin/machine_spec.xml';
    push @c, ($ENV{HOME} // '') . '/.amin/machine_spec.xml' if $ENV{HOME};
    my $bundled = abs_path(dirname(__FILE__) . '/machine_spec.xml');
    push @c, $bundled if $bundled;
    return @c;
}

sub _parse ($self, $xml) {
    my $result = {
        allowed   => undef,
        filters   => [],
        handler   => undef,
        log       => undef,
        generator => undef,
        name      => undef,
        ui_dialects => {},
        # Raw spec-declared BSAX vocabulary band names (document order).  The
        # codec drops core names and assigns band NAME_IDs — see
        # Amin::{Handler,Generator}::BSAX.
        vocab     => [],
    };
    my $degrade = sub {
        $result->{allowed} = $self->{_from_bitcache} ? {} : $self->_allow_all_registered;
        return $result;
    };
    return $degrade->() if !defined $xml || !length $xml;

    # The machine spec is XML too, so read it with the machine's SAX driver
    # (LibXML when the host has it, pure Perl otherwise) instead of hard-
    # requiring a C XML library a cross-built node does not carry.  The
    # stream stays event-by-event — same collector, no DOM.
    require Amin::Generator::XML;
    my $c = Amin::Machine::MachineSpec::Collector->new;
    my $ok = eval { Amin::Generator::XML->new(Handler => $c)->parse_string($xml); 1 };
    return $degrade->() unless $ok;

    my %allowed;
    $allowed{$_->{class}} = 1 for $c->{filters}->@*;
    $result->{filters} = $c->{filters};
    $result->{vocab}   = $c->{vocab_names};
    $result->{allowed} = (scalar keys %allowed) ? \%allowed
        : ($self->{_from_bitcache} ? {} : $self->_allow_all_registered);

    # ui: render targets are contract facts too: which dialect class serves a
    # profile-declared target (ios/android).  The Dispatcher reads this to build
    # the shared render context the ui: element filters inject as `Render`.
    $result->{ui_dialects} = $c->{ui_dialects};

    for my $tag (qw(handler log generator)) {
        $result->{$tag} = $c->{$tag} if $c->{$tag};
    }
    $result->{name} = $c->{name} if defined $c->{name};
    return $result;
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
        filters => [], ui_dialects => {}, name => undef,
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
        push $self->{vocab_names}->@*, $a{element}
            if defined $a{element} && length $a{element};
    }
    elsif ($name eq 'ui-dialect') {
        my ($t, $c) = ($a{target}, $a{class} // $a{name});
        if (defined $t && length $t && defined $c && length $c) {
            $self->{ui_dialects}{$t} = { class => $c };
        }
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
