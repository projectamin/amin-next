package Amin::UCC::Article;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin::UCC qw(UCC_NS);
use Class::Tiny qw(Handler Log Mode Name Element), {
    _cap      => 0,
    _buf      => '',
    _children => sub { +{} },
    _cur      => undef,
    _start_el => undef,
};

my $UCC = UCC_NS();

sub _mine ($self, $e) { ($e->{NamespaceURI} // '') eq $UCC }

sub _attr ($self, $e, $name) {
    return undef unless $e && $e->{Attributes};
    for my $k ("{}" . $name, "{$UCC}$name") {
        return $e->{Attributes}{$k}{Value}
            if exists $e->{Attributes}{$k}
            && defined $e->{Attributes}{$k}{Value};
    }
    return undef;
}

sub _child_vals ($self, $name) {
    $self->{_children}{$name} // [];
}

sub _emit_event ($self, $article, $kind, %vals) {
    my $h = $self->Handler or return;
    $vals{article} = $article;
    $vals{kind}    = $kind;
    my %attrs;
    for my $k (keys %vals) {
        my $v = defined $vals{$k} ? "$vals{$k}" : '';
        $attrs{"{}" . $k} = {
            Name         => "ucc:$k",
            LocalName    => $k,
            Prefix       => 'ucc',
            NamespaceURI => $UCC,
            Value        => $v,
        };
    }
    $h->start_element({
        NamespaceURI => $UCC, LocalName => 'event',
        Name => 'ucc:event', Prefix => 'ucc', Attributes => \%attrs,
    });
    $h->end_element({
        NamespaceURI => $UCC, LocalName => 'event',
        Name => 'ucc:event', Prefix => 'ucc',
    });
    return;
}

sub _result ($self, %m) {
    my $h = $self->Handler or return;
    my $mk = sub ($n, $v) {
        "{}" . $n => {
            Name         => "ucc:$n",
            LocalName    => $n,
            Prefix       => 'ucc',
            NamespaceURI => $UCC,
            Value        => defined($v) ? "$v" : '',
        };
    };
    $h->start_element({
        NamespaceURI => $UCC, LocalName => 'result',
        Name => 'ucc:result', Prefix => 'ucc',
        Attributes => { $mk->('kind', $m{kind}) },
    });
    $h->start_element({
        NamespaceURI => $UCC, LocalName => 'status',
        Name => 'ucc:status', Prefix => 'ucc',
        Attributes => {
            $mk->('kind',      $m{kind}),
            $mk->('rc',        $m{rc}        // 0),
            $mk->('exit_kind', $m{exit_kind} // 'ok'),
            $mk->('msg',       $m{msg}       // ''),
        },
    });
    $h->end_element({
        NamespaceURI => $UCC, LocalName => 'status',
        Name => 'ucc:status', Prefix => 'ucc',
    });
    $h->end_element({
        NamespaceURI => $UCC, LocalName => 'result',
        Name => 'ucc:result', Prefix => 'ucc',
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
