package Amin::AI::Article;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin::AI qw(AI_NS);
use Class::Tiny qw(Handler Log Mode Name Element), {
    _cap      => 0,
    _buf      => '',
    _children => sub { +{} },
    _cur      => undef,
    _start_el => undef,
};

my $AI = AI_NS();

sub _mine ($self, $e) { ($e->{NamespaceURI} // '') eq $AI }

sub _attr ($self, $e, $name) {
    return undef unless $e && $e->{Attributes};
    for my $k ("{}" . $name, "{$AI}$name") {
        return $e->{Attributes}{$k}{Value}
            if exists $e->{Attributes}{$k}
            && defined $e->{Attributes}{$k}{Value};
    }
    return undef;
}

sub _child_vals ($self, $name) {
    $self->{_children}{$name} // [];
}

sub _xmlns_ai_attr ($self) {
    my $AI = AI_NS();
    return '{http://www.w3.org/2000/xmlns/}ai' => {
        Name => 'xmlns:ai', LocalName => 'ai', Prefix => 'xmlns',
        NamespaceURI => 'http://www.w3.org/2000/xmlns/',
        Value => $AI,
    };
}

sub _filter_id ($self) {
    state $cache = {};
    my $pkg = ref($self);
    return $cache->{$pkg} if exists $cache->{$pkg};
    my $h;
    if (eval { require Digest::BLAKE3; 1 }) {
        $h = Digest::BLAKE3::blake3($pkg);
    } elsif (eval { require Digest::SHA3; 1 }) {
        $h = Digest::SHA3->new(256)->add($pkg)->hexdigest;
    } else {
        $h = unpack('H*', $pkg);
    }
    $cache->{$pkg} = $h;
    return $h;
}

sub _provenance_attrs ($self, %extra) {
    my %out = (
        '{}provenance.author_kind' => {
            Name => 'ai:provenance.author_kind', LocalName => 'provenance.author_kind',
            Prefix => 'ai', NamespaceURI => $AI, Value => 'ai',
        },
        '{}provenance.filter_id' => {
            Name => 'ai:provenance.filter_id', LocalName => 'provenance.filter_id',
            Prefix => 'ai', NamespaceURI => $AI, Value => $self->_filter_id,
        },
        '{}provenance.tier' => {
            Name => 'ai:provenance.tier', LocalName => 'provenance.tier',
            Prefix => 'ai', NamespaceURI => $AI, Value => $extra{tier} // 0,
        },
    );
    if (defined $extra{model_id}) {
        $out{'{}provenance.model_id'} = {
            Name => 'ai:provenance.model_id', LocalName => 'provenance.model_id',
            Prefix => 'ai', NamespaceURI => $AI, Value => $extra{model_id},
        };
    }
    return %out;
}

sub _emit_ai ($self, $local, %vals) {
    my $h = $self->Handler or return;
    my %attrs;
    for my $k (keys %vals) {
        my $v = defined $vals{$k} ? "$vals{$k}" : '';
        $attrs{"{}" . $k} = {
            Name         => "ai:$k",
            LocalName    => $k,
            Prefix       => 'ai',
            NamespaceURI => $AI,
            Value        => $v,
        };
    }
    %attrs = (%attrs, $self->_provenance_attrs(%vals), $self->_xmlns_ai_attr);
    $h->start_element({
        NamespaceURI => $AI, LocalName => $local,
        Name => "ai:$local", Prefix => 'ai', Attributes => \%attrs,
    });
    $h->end_element({
        NamespaceURI => $AI, LocalName => $local,
        Name => "ai:$local", Prefix => 'ai',
    });
    return;
}

sub start_element ($self, $el) {
    my $want = $self->element // '';
    my $ln   = $el->{LocalName} // '';
    if ($self->_mine($el) && length($want) && $ln eq $want) {
        $self->{_cap}      = 1;
        $self->{_children} = {};
        $self->{_buf}      = '';
        $self->{_cur}      = undef;
        $self->{_start_el} = $el;
        return $self->SUPER::start_element($el);
    }
    if ($self->{_cap} && $self->_mine($el)) {
        $self->{_cur} = $ln;
        $self->{_buf} = '';
    }
    return $self->SUPER::start_element($el);
}

sub characters ($self, $d) {
    $self->{_buf} .= $d->{Data} // '' if $self->{_cap};
    return $self->SUPER::characters($d);
}

sub end_element ($self, $el) {
    my $ln = $el->{LocalName} // '';
    if ($self->{_cap} && $self->_mine($el)) {
        if (defined $self->{_cur} && $self->{_cur} eq $ln) {
            my $t = $self->{_buf};
            $t =~ s/^\s+|\s+$//g;
            push $self->{_children}{$ln}->@*, $t;
            $self->{_cur} = undef;
            $self->{_buf} = '';
        }
        if (defined($self->element) && $ln eq $self->element) {
            $self->{_cap} = 0;
            $self->on_article_close($self->{_start_el} // $el);
        }
    }
    return $self->SUPER::end_element($el);
}

sub on_article_close ($self, $el) { return; }

1;
