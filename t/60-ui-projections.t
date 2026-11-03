#!/usr/bin/env perl
# The `ui:` projection fleet: one late filter per ui: kind.
#
#   <ui:*>  ──neutral host──▶  forwarded untouched in full (--os=tty;
#                              no candidate has a matching target, so nothing
#                              is spliced — a profile can cross many machines
#                              before it reaches one that renders it)
#           ──ios──────────▶  <amin:stream channel="ui-swiftui">…Swift…</amin:stream>
#                              prepended per element, <ui:*> still forwarded
#           ──android──────▶  <amin:stream channel="ui-compose">…Kotlin…</amin:stream>
#                              prepended per element, <ui:*> still forwarded
#           ──html─────────▶  real html:* XHTML events (never from a string),
#                              per element, <ui:*> still forwarded
#
# Proves the closed-world Guard fails closed everywhere; that a neutral host
# passes the whole ui: subtree through in full; that a target host splices
# exactly one element filter per kind and the fragments it emits concatenate to
# the target's whole projection, byte for byte (the streaming form of the
# retired render_tree); and that the target → dialect binding is a spec fact.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use XML::LibXML::SAX;
use Amin::Log::Standard;
use Amin::Machine::MachineSpec;
use Amin::Machine::Dispatcher;

my $AMIN_NS = 'http://projectamin.org/ns/2026/';
my $UI_NS   = 'http://projectamin.org/ns/ui/1';

my @KINDS = qw(
    app scene list row column hstack vstack stack grid section card
    progress alert sheet toolbar searchable item label text badge
    sparkline button navigate image asyncimage
);

# Minimal SAX sink: records raw events so assertions read the fleet's real
# output (no Writer round-trip, which would re-indent generated source).
{
    package UICapture;
    use v5.38; use warnings; use experimental 'signatures';

    sub new ($class, %o) { bless { events => [], %o }, $class }

    sub start_element ($self, $el) {
        push $self->{events}->@*,
            [ 'start', $el->{Name} // $el->{LocalName} // '', $el->{Attributes} // {} ];
    }
    sub end_element ($self, $el) {
        push $self->{events}->@*, [ 'end', $el->{Name} // $el->{LocalName} // '' ];
    }
    sub characters ($self, $d) { push $self->{events}->@*, [ 'chars', $d->{Data} // '' ] }
    sub start_document ($self, @) { }
    sub end_document   ($self, @) { }

    # Start-element names, in stream order.
    sub names ($self) {
        map { $_->[1] } grep { $_->[0] eq 'start' } $self->{events}->@*
    }
    # The ui:* start-elements, in stream order.
    sub ui_names ($self) { grep { /^ui:/ } $self->names }
    sub attrs_of ($self, $name) {
        for my $e ($self->{events}->@*) {
            next unless $e->[0] eq 'start' && $e->[1] eq $name;
            my %v;
            for my $a (values %{ $e->[2] }) { $v{ $a->{LocalName} // '' } = $a->{Value} }
            return \%v;
        }
        return {};
    }
    # Concatenated text of every <amin:stream channel="$ch"> element, in order.
    # The fleet emits one fragment sibling per verb, so this is the whole
    # projection.
    sub stream_of ($self, $ch) {
        my ($want, $out) = (0, '');
        for my $e ($self->{events}->@*) {
            if ($e->[0] eq 'start' && $e->[1] eq 'amin:stream') {
                my %v;
                for my $at (values %{ $e->[2] }) { $v{ $at->{LocalName} // '' } = $at->{Value} }
                $want = (($v{channel} // '') eq $ch);
                next;
            }
            if ($e->[0] eq 'end' && $e->[1] eq 'amin:stream') { $want = 0; next }
            $out .= $e->[1] if $want && $e->[0] eq 'chars';
        }
        return $out;
    }
}

sub doc ($inner) {
    return '<?xml version="1.0" encoding="UTF-8"?>'
        . '<amin:profile xmlns:amin="' . $AMIN_NS . '"'
        . ' xmlns:ui="' . $UI_NS . '">'
        . $inner . '</amin:profile>';
}

# A Dispatcher whose chain is built for one target — exactly the real
# composition path (spec → _LazyGate → spliced element filters).  Feed it with
# XML::LibXML::SAX so events arrive one at a time.
sub fleet ($os, $cap, $log) {
    return Amin::Machine::Dispatcher->new(
        Handler => $cap, Log => $log, Mode => 'render', ui_os => $os);
}

sub drive ($filter, $xml) {
    XML::LibXML::SAX->new(Handler => $filter)->parse_string($xml);
    return;
}

my $DEMO = doc(
    '<ui:app title="Demo">'
    . '<ui:vstack spacing="4">'
    . '<ui:text kind="headline">hi</ui:text>'
    . '<ui:button title="Go" />'
    . '</ui:vstack>'
    . '</ui:app>'
);

# ═══════════════════════════════════════════════════════════════════════════
# A. A neutral host forwards the whole ui: subtree untouched.
# ═══════════════════════════════════════════════════════════════════════════
subtest 'A: a neutral (tty) host forwards the ui: subtree untouched' => sub {
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $cap = UICapture->new;
    drive(fleet('tty', $cap, $log), $DEMO);

    is([$cap->ui_names], ['ui:app', 'ui:vstack', 'ui:text', 'ui:button'],
        'A1: the whole ui: subtree rides through, in order, untouched');
    is($cap->attrs_of('ui:app')->{title}, 'Demo', 'A2: ui:app title preserved');
    is($cap->attrs_of('ui:vstack')->{spacing}, '4', 'A3: ui:vstack spacing preserved');
    is($cap->attrs_of('ui:text')->{kind}, 'headline', 'A4: ui:text kind preserved');
    is($cap->stream_of('ui-swiftui'), '', 'A5: nothing spliced — no ui-swiftui fragment');
    is($cap->stream_of('ui-compose'), '', 'A6: nothing spliced — no ui-compose fragment');
    is($log->error_count, 0, 'A7: known vocabulary logs nothing');
};

# ═══════════════════════════════════════════════════════════════════════════
# B. The neutral Guard fails closed on every host, render target or not.
# ═══════════════════════════════════════════════════════════════════════════
subtest 'B: the Guard fails closed on an unknown ui: kind' => sub {
    my $xml = doc('<ui:vstack><ui:widget><ui:text>secret</ui:text></ui:widget></ui:vstack>');
    for my $os (qw(tty ios)) {
        my $log = Amin::Log::Standard->new(stderr => 0);
        my $cap = UICapture->new;
        drive(fleet($os, $cap, $log), $xml);

        cmp_ok($log->error_count, '>', 0, "B[$os]: unknown kind logged as an error");
        is([$cap->ui_names], ['ui:vstack'],
            "B[$os]: unknown subtree dropped — no ui:widget, no leaked child");
    }
};

# ═══════════════════════════════════════════════════════════════════════════
# C. An ios host projects the IR to SwiftUI — additively.
# ═══════════════════════════════════════════════════════════════════════════
subtest 'C: an ios host projects the IR to SwiftUI' => sub {
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $cap = UICapture->new;
    drive(fleet('ios', $cap, $log), $DEMO);

    my $src = $cap->stream_of('ui-swiftui');
    is($src,
       "struct DemoView: View {\n"
       . "    var body: some View {\n"
       . "    VStack(spacing: 4) {\n"
       . "        Text(\"hi\")\n"
       . "        Button(\"Go\") { }\n"
       . "    }\n"
       . "    }\n"
       . "}",
       'C1: the per-element fragments concatenate to the whole projection');
    like($src, qr/struct DemoView: View/, 'C2: ui:app → a SwiftUI View struct');
    like($src, qr/VStack\(spacing: 4\)/,  'C3: ui:vstack spacing → VStack(spacing:)');
    like($src, qr/Text\("hi"\)/,          'C4: ui:text body text reaches the projection');
    like($src, qr/Button\("Go"\)/,        'C5: ui:button title → Button title');
    is([$cap->ui_names], ['ui:app', 'ui:vstack', 'ui:text', 'ui:button'],
        'C6: additive — the ui: subtree is still emitted in full');
    like(join(' ', $cap->names), qr/amin:stream ui:app /,
        'C7: the fragment is a sibling *before* the element (additive prepend)');
    is($cap->stream_of('ui-compose'), '', 'C8: only the ios dialect is spliced');
};

# ═══════════════════════════════════════════════════════════════════════════
# D. An android host projects the same IR to Kotlin/Compose.
# ═══════════════════════════════════════════════════════════════════════════
subtest 'D: an android host projects the same IR to Kotlin/Compose' => sub {
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $cap = UICapture->new;
    drive(fleet('android', $cap, $log), $DEMO);

    my $src = $cap->stream_of('ui-compose');
    is($src,
       "\@Composable\n"
       . "fun Demo() {\n"
       . "    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {\n"
       . "        Text(\"hi\")\n"
       . "        Button(onClick = { }) { Text(\"Go\") }\n"
       . "    }\n"
       . "}",
       'D1: the per-element fragments concatenate to the whole projection');
    like($src, qr/\@Composable\n/, 'D2: ui:app → an @Composable function');
    like($src, qr/fun Demo\(\)/,   'D3: function named from ui:app title');
    like($src, qr/Column\(verticalArrangement = Arrangement\.spacedBy\(4\.dp\)\)/,
        'D4: ui:vstack spacing → Column spacedBy');
    like($src, qr/Button\(onClick = \{ \}\) \{ Text\("Go"\) \}/,
        'D5: childless ui:button → Button with a Text label');
    is([$cap->ui_names], ['ui:app', 'ui:vstack', 'ui:text', 'ui:button'],
        'D6: additive — the ui: subtree is still emitted in full');
    is($cap->stream_of('ui-swiftui'), '', 'D7: only the android dialect is spliced');
};

# ═══════════════════════════════════════════════════════════════════════════
# E. The machine spec declares the fleet, the Guard and the dialect binding.
# ═══════════════════════════════════════════════════════════════════════════
subtest 'E: machine_spec declares the ui: filter family' => sub {
    my $spec = Amin::Machine::MachineSpec->new->spec;
    my @all  = $spec->{filters}->@*;

    ok(!(grep { $_->{class} =~ /^Amin::Filter::UI::(Tree|SwiftUI|Compose)$/ } @all),
        'E1: the retired monolith projectors are gone');
    ok(!(grep { $_->{class} =~ /SwiftUIView/ } @all),
        'E2: the retired SwiftUIView stub is gone');

    my @el = grep { $_->{class} =~ /^Amin::Filter::UI::Element::/ } @all;
    is(scalar @el, 75, 'E3: one element filter per kind per target (25 × 3)');
    is([sort map { $_->{meta}{position} // '' } @el], [('late') x 75],
        'E4: every element filter sits at the late position');
    is([sort keys %{ { map { ($_->{meta}{target} // '') => 1 } @el } }], ['android', 'html', 'ios'],
        'E5: every element filter is target-scoped (ios / android / html only)');

    my @ios_kinds = sort map { $_->{meta}{element} } grep { ($_->{meta}{target} // '') eq 'ios' } @el;
    is(scalar @ios_kinds, 25, 'E6: 25 ios candidates');
    is(\@ios_kinds, [sort @KINDS], 'E7: the candidates cover the closed-world ui: vocabulary');

    my @guard = grep { $_->{class} eq 'Amin::Filter::UI::Guard' } @all;
    is(scalar @guard, 1, 'E8: the neutral Guard is declared once');
    is($guard[0]{meta}{position}, 'late', 'E9: the Guard is a late filter');

    is($spec->{ui_dialects},
        { ios     => { class => 'Amin::UI::Target::SwiftUI' },
          android => { class => 'Amin::UI::Target::Compose' },
          html    => { class => 'Amin::UI::Target::HTML' } },
        'E10: the target → dialect binding is a spec fact, not a class-name rule');
};

# ═══════════════════════════════════════════════════════════════════════════
# F. `title` is authored text, not a symbol — both projections fold it to a
#    legal identifier.
# ═══════════════════════════════════════════════════════════════════════════
subtest 'F: free-form titles fold to legal identifiers' => sub {
    my $xml = doc('<ui:app title="Amin Fabric — Shop"><ui:text>hi</ui:text></ui:app>');

    my $log = Amin::Log::Standard->new(stderr => 0);
    my $sc  = UICapture->new;
    drive(fleet('ios', $sc, $log), $xml);
    like($sc->stream_of('ui-swiftui'), qr/struct AminFabricShopView: View/,
        'F1: SwiftUI type name is a valid identifier');

    my $cc = UICapture->new;
    drive(fleet('android', $cc, $log), $xml);
    like($cc->stream_of('ui-compose'), qr/fun AminFabricShop\(\)/,
        'F2: Compose function name is a valid identifier');
};

# ═══════════════════════════════════════════════════════════════════════════
# G. An html host projects the IR to XHTML SAX events (never from a string).
# ═══════════════════════════════════════════════════════════════════════════
subtest 'G: an html host projects the IR to XHTML events' => sub {
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $cap = UICapture->new;
    drive(fleet('html', $cap, $log), $DEMO);

    my @n = $cap->names;
    ok((grep { $_ eq 'html' } @n),   'G1: ui:app opens <html> (the page root)');
    ok((grep { $_ eq 'title' } @n),  'G2: ui:app title → <title>');
    ok((grep { $_ eq 'p' } @n),      'G3: ui:text → <p>');
    ok((grep { $_ eq 'button' } @n), 'G4: ui:button → <button>');
    is([$cap->ui_names], ['ui:app', 'ui:vstack', 'ui:text', 'ui:button'],
        'G5: additive — the ui: subtree is still emitted in full');
    is($cap->stream_of('ui-swiftui'), '', 'G6: the ios dialect is not spliced');
    is($cap->stream_of('ui-compose'), '', 'G7: the android dialect is not spliced');
};

done_testing;
