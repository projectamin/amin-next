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
        $result->{allowed} = $self->_allow_all_registered;
        return $result;
    }
    require XML::LibXML;
    my $doc = eval { XML::LibXML->load_xml(string => $xml) };
    if ($@ || !$doc) {
        $result->{allowed} = $self->_allow_all_registered;
        return $result;
    }
    my %allowed;
    for my $node ($doc->findnodes('//filter')) {
        my $class = $node->getAttribute('class') // $node->getAttribute('name');
        next unless defined $class && length $class;
        $allowed{$class} = 1;
    }
    $result->{allowed} = (scalar keys %allowed) ? \%allowed : $self->_allow_all_registered;

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
