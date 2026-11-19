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
        # `type` is the response media type this route produces; it selects the
        # serializer in the adapter (HTML by default, text/plain for a byte-exact
        # body such as an ACME HTTP-01 authorization).  It is deliberately a
        # property of the ROUTE, not of any filter, so any route — in any app,
        # under any composed filter set — can choose how its profile is served.
        my $type = $node->getAttribute('type');
        $type = undef unless defined $type && length $type;
        if ($ln eq 'route') {
            my $path = $node->getAttribute('path');
            die "axa:route missing path\n" unless defined $path && length $path;
            push @routes, {
                path     => $path,
                method   => uc($node->getAttribute('method') // 'GET'),
                type     => $type,
                file     => _file_attr($node),
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
                type     => $type,
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

# `file=` turns a GET route into a byte route: the value is a path template
# (`$VAR` / `${VAR}` expand from the environment at request time; a `:name`
# segment captures one request segment under Amin::AXA::HTTP's confinement
# rules).  Such a route never renders a profile — it answers with the file's
# bytes — so any app can hand a browser an artifact without a second server.
sub _file_attr ($node) {
    my $f = $node->getAttribute('file');
    return undef unless defined $f && length $f;
    return $f;
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

# ── path templates ──────────────────────────────────────────────────────────
# A declared path is a template: `/`-separated segments where a segment of the
# form `:name` captures the matching request segment and every other segment
# must match literally.  Capture is RAW — the request path is the bytes the
# transport split off the request line (never percent-decoded), so a template
# and a path are compared byte for byte; the Rust peer's matcher does the same,
# which is what keeps the two fronts' routing decisions identical (§7).
sub match_path ($class, $template, $path) {
    my @t = split m{/}, $template, -1;
    my @p = split m{/}, $path, -1;
    return undef unless @t == @p;
    my %params;
    for my $i (0 .. $#t) {
        my $seg = $t[$i];
        if (length($seg) > 1 && substr($seg, 0, 1) eq ':') {
            return undef unless length $p[$i];
            $params{ substr($seg, 1) } = $p[$i];
        }
        elsif ($seg ne $p[$i]) {
            return undef;
        }
    }
    return \%params;
}

# The first GET route whose template matches `$path`.  Scalar context returns
# the route (the pre-template contract); list context returns the route and the
# captured parameters, which the adapter folds into the render values.
sub get_route ($self, $path) {
    for my $r ($self->{routes}->@*) {
        next unless $r->{method} eq 'GET';
        my $params = $self->match_path($r->{path}, $path) // next;
        return wantarray ? ($r, $params) : $r;
    }
    return wantarray ? () : undef;
}
sub routes_at  ($self, $path) { grep { defined $self->match_path($_->{path}, $path) } $self->{routes}->@* }
sub actions_at ($self, $path) { grep { defined $self->match_path($_->{path}, $path) } $self->{actions}->@* }
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
