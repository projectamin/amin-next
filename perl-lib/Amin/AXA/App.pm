package Amin::AXA::App;
use v5.38; use warnings; use utf8;
use XML::LibXML;
use Class::Tiny qw(id dir);   # routes/actions/catalog are plain hash keys with subs below

# Loads an app bundle's OWN declarations (plan §4.1/§4.2/§M3):
#   axa.xml            routes + actions: the fragment the app declares for
#                      each path/method, placeholders intact
#   data/catalog.xml   products, in memory for the lifetime of the process
# Boot-time only and read-only afterwards (§4.9: safe to keep — the parsed
# declarations are never mutated after load).
#
# Route/action lookup lives here because it reads declarations; *substituting*
# request values into the declared fragment is Amin::AXA::FormCodec's job.
# Neither knows what a shop is.

my $DEFAULT;
sub set_default ($class, $app) { $DEFAULT = $app; return $DEFAULT }
sub default ($class) { $DEFAULT }

sub load ($class, $dir) {
    die "app bundle not a directory: $dir\n" unless -d $dir;
    my $axa = "$dir/axa.xml";
    die "app bundle missing axa.xml: $axa\n" unless -f $axa;
    my $doc  = XML::LibXML->load_xml(location => $axa);
    my $root = $doc->documentElement;

    my (@routes, @actions);
    for my $node ($root->childNodes) {
        next unless $node->nodeType == XML_ELEMENT_NODE;
        my $ln   = $node->localname // '';
        my $frag = join '', map { $_->toString } $node->childNodes;
        if ($ln eq 'route') {
            my $path = $node->getAttribute('path');
            die "axa:route missing path\n" unless defined $path && length $path;
            push @routes, {
                path     => $path,
                method   => uc($node->getAttribute('method') // 'GET'),
                fragment => $frag,
            };
        }
        elsif ($ln eq 'action') {
            my $name = $node->getAttribute('name');
            my $path = $node->getAttribute('path');
            die "axa:action missing name\n" unless defined $name && length $name;
            die "axa:action missing path\n" unless defined $path && length $path;
            push @actions, {
                name     => $name,
                path     => $path,
                method   => uc($node->getAttribute('method') // 'POST'),
                fragment => $frag,
            };
        }
        else {
            die "axa.xml: unknown element <axa:$ln>\n";
        }
    }
    die "axa.xml declares no routes\n" unless @routes;

    return bless {
        id      => $root->getAttribute('id') // $root->getAttribute('name') // $dir,
        dir     => $dir,
        routes  => \@routes,
        actions => \@actions,
        catalog => _load_catalog("$dir/data/catalog.xml"),
    }, $class;
}

sub _load_catalog ($file) {
    return [] unless -f $file;
    my $doc = XML::LibXML->load_xml(location => $file);
    my @products;
    for my $p ($doc->getElementsByTagNameNS('*', 'product')) {
        push @products, { map { $_ => $p->getAttribute($_) // '' } qw(sku name price stock) };
    }
    return \@products;
}

# Exact-path matching only (first pass; patterns come with routing).
sub get_route ($self, $path) {
    for my $r ($self->{routes}->@*) {
        return $r if $r->{path} eq $path && $r->{method} eq 'GET';
    }
    return undef;
}
sub routes_at  ($self, $path) { grep { $_->{path} eq $path } $self->{routes}->@* }
sub actions_at ($self, $path) { grep { $_->{path} eq $path } $self->{actions}->@* }
sub action_named ($self, $name) {
    for my $a ($self->{actions}->@*) { return $a if $a->{name} eq $name }
    return undef;
}
sub product ($self, $sku) {
    for my $p ($self->{catalog}->@*) { return $p if $p->{sku} eq ($sku // '') }
    return undef;
}
sub catalog ($self) { $self->{catalog} }

1;
