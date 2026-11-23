package Amin::Filter::Map::Topology;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Class::Tiny qw(Handler Log Mode Name Element Render),
    { nodes => sub { {} }, edges => sub { [] }, regions => sub { [] },
      active_server_id => undef, depth => 0, link_depth => 0, emitted => 0 };

use constant MAP_NS => 'http://projectamin.org/ns/map/1';

sub _attr ($e, $name) {
    ($e->{Attributes}{"{}${name}"} // {})->{Value} // '';
}

sub start_element ($self, $e) {
    $self->{depth}++;
    my $ns  = $e->{NamespaceURI} // '';
    my $ln  = $e->{LocalName}     // '';
    if ($ns eq MAP_NS) {
        if    ($ln eq 'region') { push $self->{regions}->@*, {
                id => _attr($e,'id'), nodes => [],
                accent => _attr($e,'accent'), bg => _attr($e,'bg'),
                meta => $e } }
        elsif ($ln eq 'server') {
            my $node = { id => _attr($e,'id'), status => 'pending',
                flavor => _attr($e,'flavor'), location => _attr($e,'location'),
                region => $self->{regions}[-1] ? $self->{regions}[-1]{id} : undef,
                meta => $e };
            $self->{nodes}{$node->{id}} = $node;
            $self->{regions}[-1]{nodes} and push
                $self->{regions}[-1]{nodes}->@*, $node->{id};
            $self->Handler && $self->Handler->start_element($e);
            $self->_emit_node($node, 'decl');
            return;
        }
        elsif ($ln eq 'link') {
            # A derived <map:link> annotation nests inside its source link; on
            # a re-feed of this output it must not become a second edge.
            my $nested = $self->{link_depth}++;
            unless ($nested) {
                my $link = { a => _attr($e,'a'), b => _attr($e,'b'),
                    cost => _attr($e,'cost') || 1,
                    color => _attr($e,'color'), meta => $e };
                push $self->{edges}->@*, $link;
                $self->Handler && $self->Handler->start_element($e);
                $self->_emit_link($link);
                return;
            }
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

# The graph is complete only when the source document is.  Open the render
# artifact here — never at map-layer close: map: elements are siblings and need
# not be contiguous, so a region close is not a completion signal.  Emitting
# before the root close keeps the fragment nested correctly in profile output;
# a dedicated artifact writer drops everything but the fragment.
sub end_element ($self, $e) {
    if (($e->{NamespaceURI} // '') eq MAP_NS
        && ($e->{LocalName} // '') eq 'link') {
        $self->{link_depth}-- if $self->{link_depth};
    }
    my $root = ($self->{depth} == 1) ? 1 : 0;
    $self->_emit_graph if $root;
    $self->{depth}-- if $self->{depth} > 0;
    $self->Handler && $self->Handler->end_element($e);
}

sub end_document ($self, @a) {
    $self->_emit_graph;
    $self->Handler && $self->Handler->end_document(@a);
}

sub characters ($self, $c) { $self->Handler && $self->Handler->characters($c) }

sub _emit_graph ($self) {
    return if $self->{emitted};
    $self->{emitted} = 1;
    my $r = $self->Render       or return;
    my $h = $self->Handler      or return;
    return unless $self->{regions}->@* || keys %{ $self->{nodes} }
                                             || $self->{edges}->@*;
    $r->emit_graph({
        regions => $self->{regions},
        nodes   => $self->{nodes},
        edges   => $self->{edges},
    }, $h);
    return;
}

sub _emit_node ($self, $node, $phase) {
    my $st = $node->{status} // 'pending';
    my %a = ( id => $node->{id}, status => $st, phase => $phase );
    $a{flavor} = $node->{flavor} if length $node->{flavor};
    $self->_emit('node', \%a);
}

sub _emit_link ($self, $link) {
    my %a = ( a => $link->{a}, b => $link->{b}, cost => $link->{cost} );
    $a{color} = $link->{color} if length $link->{color};
    $self->_emit('link', \%a);
}

sub _emit ($self, $ln, $a) {
    my $h = $self->Handler or return;
    my $attrs = { map {; "{}" . $_ => +{ Name => $_, LocalName => $_,
        Prefix => 'map', NamespaceURI => MAP_NS,
        Value => $a->{$_} } } keys %$a };
    $h->start_element({ NamespaceURI => MAP_NS,
        LocalName => $ln, Name => "map:$ln", Prefix => 'map',
        Attributes => $attrs });
    $h->end_element({   NamespaceURI => MAP_NS,
        LocalName => $ln, Name => "map:$ln", Prefix => 'map' });
}

1;
