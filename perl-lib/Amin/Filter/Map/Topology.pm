package Amin::Filter::Map::Topology;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Class::Tiny qw(Handler Log Mode Name Element),
    { nodes => sub { {} }, edges => sub { [] }, regions => sub { [] }, active_server_id => undef };

sub _attr ($e, $name) {
    ($e->{Attributes}{"{}${name}"} // {})->{Value} // '';
}

sub start_element ($self, $e) {
    my $ns  = $e->{NamespaceURI} // '';
    my $ln  = $e->{LocalName}     // '';
    if ($ns eq 'http://projectamin.org/ns/map/1') {
        if    ($ln eq 'region') { push $self->{regions}->@*, {
                id => _attr($e,'id'), nodes => [], meta => $e } }
        elsif ($ln eq 'server') {
            my $node = { id => _attr($e,'id'), status => 'pending',
                flavor => _attr($e,'flavor'), meta => $e };
            $self->{nodes}{$node->{id}} = $node;
            $self->{regions}[-1]{nodes} and push
                $self->{regions}[-1]{nodes}->@*, $node->{id};
            $self->Handler && $self->Handler->start_element($e);
            $self->_emit_node($node, 'decl');
            return;
        }
        elsif ($ln eq 'link') {
            my $link = { a => _attr($e,'a'), b => _attr($e,'b'),
                cost => _attr($e,'cost') || 1,
                color => _attr($e,'color'), meta => $e };
            push $self->{edges}->@*, $link;
            $self->Handler && $self->Handler->start_element($e);
            return;
        }
    }
    if ($ln eq 'status' && ($e->{NamespaceURI}//'') =~ /projectamin/) {
        my $kind = _attr($e,'kind');
        my $id   = $self->{active_server_id};
        if (defined $id && $self->{nodes}{$id}) {
            $self->{nodes}{$id}{status} = $kind if length $kind;
            $self->_emit_node($self->{nodes}{$id}, 'result');
        }
    }
    if ($ln eq 'command' && ($e->{NamespaceURI}//'') =~ /projectamin/) {
        my $name = _attr($e,'name');
        $self->{active_server_id} = _attr($e,'target') || undef if $name eq 'connect';
    }
    $self->Handler && $self->Handler->start_element($e);
}

sub end_element   ($self, $e) { $self->Handler && $self->Handler->end_element($e) }
sub characters    ($self, $c) { $self->Handler && $self->Handler->characters($c) }

sub _emit_node ($self, $node, $phase) {
    my $h = $self->Handler or return;
    my $st = $node->{status} // 'pending';
    my %a = ( id => $node->{id}, status => $st, phase => $phase );
    $a{flavor} = $node->{flavor} if length $node->{flavor};
    my $attrs = { map {; "{}" . $_ => +{ Name => $_, LocalName => $_,
        Prefix => 'map', NamespaceURI => 'http://projectamin.org/ns/map/1',
        Value => $a{$_} } } keys %a };
    $h->start_element({ NamespaceURI => 'http://projectamin.org/ns/map/1',
        LocalName => 'node', Name => 'map:node', Prefix => 'map',
        Attributes => $attrs });
    $h->end_element({   NamespaceURI => 'http://projectamin.org/ns/map/1',
        LocalName => 'node', Name => 'map:node', Prefix => 'map' });
}

1;
