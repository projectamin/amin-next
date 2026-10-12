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

sub _load ($self) {
    if (defined $self->{xml}) {
        return $self->{xml};
    }
    if (defined $self->{bc_hash} && length $self->{bc_hash}) {
        $self->{_from_bitcache} = 1;
        my $raw = $self->_bctool_get($self->{bc_hash});
        return undef unless defined $raw && length $$raw;
        return undef unless $self->_bctool_verify;
        return $$raw;
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
        handler   => undef,
        log       => undef,
        generator => undef,
        name      => undef,
    };
    if (!defined $xml || !length $xml) {
        if ($self->{_from_bitcache}) {
            $result->{allowed} = {};
        } else {
            $result->{allowed} = $self->_allow_all_registered;
        }
        return $result;
    }
    require XML::LibXML;
    my $doc = eval { XML::LibXML->load_xml(string => $xml) };
    if ($@ || !$doc) {
        if ($self->{_from_bitcache}) {
            $result->{allowed} = {};
        } else {
            $result->{allowed} = $self->_allow_all_registered;
        }
        return $result;
    }
    my %allowed;
    for my $node ($doc->findnodes('//filter')) {
        my $class = $node->getAttribute('class') // $node->getAttribute('name');
        next unless defined $class && length $class;
        $allowed{$class} = 1;
    }
    $result->{allowed} = (scalar keys %allowed) ? \%allowed
        : ($self->{_from_bitcache} ? {} : $self->_allow_all_registered);

    for my $tag (qw(handler log generator)) {
        my ($node) = $doc->findnodes("//$tag");
        next unless $node;
        my $class = $node->getAttribute('class') // $node->getAttribute('name');
        next unless defined $class && length $class;
        my %attrs;
        for my $a ($node->attributes) {
            my $ln = $a->localName;
            next if $ln eq 'class' || $ln eq 'name';
            $attrs{$ln} = $a->value;
        }
        $result->{$tag} = { class => $class, attrs => \%attrs };
    }
    my ($name_node) = $doc->findnodes('//name');
    if ($name_node) {
        my $t = $name_node->textContent;
        $t =~ s/^\s+|\s+$//g;
        $result->{name} = $t if length $t;
    }
    return $result;
}

sub _bctool ($self) {
    state $default = do {
        require File::Basename;
        require Cwd;
        my $root = Cwd::abs_path(File::Basename::dirname(__FILE__)
            . '/../../../rust/target/debug/bctool');
        (defined $root && -x $root) ? $root : 'bctool';
    };
    return $self->{bctool_path} if defined $self->{bctool_path};
    return $default;
}

sub _slab ($self) {
    state $default = do {
        require File::Temp;
        File::Temp::tempdir(CLEANUP => 1) . '/default.slab';
    };
    my $p = $self->{slab_path};
    return (defined $p && length $p) ? $p : $default;
}

sub _bctool_get ($self, $hash) {
    return unless defined $hash && length($hash) == 64;
    require IPC::Run;
    my $bctool = $self->_bctool;
    my $slab   = $self->_slab;
    my ($in, $out, $err) = ('', '', '');
    my $h = IPC::Run::harness(
        [$bctool, 'get', '--slab', $slab, '--hash', $hash],
        \$in, \$out, \$err, debug => 0);
    eval { IPC::Run::start($h); IPC::Run::finish($h) };
    my $rc = $? >> 8;
    if ($@ || $rc != 0) {
        return;
    }
    return \$out;
}

sub _bctool_verify ($self) {
    my $name = $self->{signer_name};
    my $ts   = $self->{signer_ts};
    my $sig  = $self->{signer_sig};
    return 0 unless defined $name && length $name;
    return 0 unless defined $ts   && length $ts;
    return 0 unless defined $sig  && length $sig;

    my $vk = $self->{signer_vk};
    unless (defined $vk && length $vk) {
        my $ta = $self->{trust_anchor_dir};
        return 0 unless defined $ta && length $ta;
        require Digest::SHA;
        my $hex = Digest::SHA::sha256_hex($name);
        $vk = "$ta/$hex.vk";
        return 0 unless -f $vk;
    }

    require IPC::Run;
    my $bctool = $self->_bctool;
    my $slab   = $self->_slab;
    my ($in, $out, $err) = ('', '', '');
    my $h = IPC::Run::harness(
        [$bctool, 'verify',
            '--slab', $slab,
            '--hash', $self->{bc_hash},
            '--name', $name,
            '--ts',   $ts,
            '--vk',   $vk,
            '--sig',  $sig],
        \$in, \$out, \$err, debug => 0);
    eval { IPC::Run::start($h); IPC::Run::finish($h) };
    my $rc = $? >> 8;
    return ($rc == 0) ? 1 : 0;
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

1;
