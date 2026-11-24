#!/usr/bin/env perl
# ui:field carries a semantic type that every target maps to its own control,
# and ui:form / ui:swap are intents (submit, apply-to-target) rather than
# HTML-only constructs.
use v5.38; use warnings; use utf8;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../perl-lib";

use Amin::UI::Target::HTML;
use Amin::UI::Target::SwiftUI;
use Amin::UI::Target::Compose;

sub A { my %h = @_; +{ map { ("{}$_" => { Value => $h{$_} }) } keys %h } }

# ── native targets ──
my $swift = Amin::UI::Target::SwiftUI->new;
my $comp  = Amin::UI::Target::Compose->new;
my %f = (
    secure    => A(type => 'secure',    name => 'k', placeholder => 'Key'),
    toggle    => A(type => 'toggle',    name => 'c', value => '1'),
    toggleoff => A(type => 'toggle',    name => 'c', value => '0'),
    multiline => A(type => 'multiline', name => 'l', value => "a\nb", lines => '6'),
    number    => A(type => 'number',    name => 'n', value => '5'),
    hidden    => A(type => 'hidden',    name => 'axa.csrf', value => 'tok'),
    text      => A(name => 'p', value => 'v'),
    unknown   => A(type => 'sparkly', name => 'p', value => 'v'),
);
my $s = sub { $swift->_leaf('field', '', $f{$_[0]}, '') };
my $c = sub { $comp->_leaf('field', '', $f{$_[0]}, '') };

like $s->('secure'),    qr/\ASecureField\("Key"/,                'SwiftUI: secure is a SecureField, labelled by the placeholder';
like $s->('toggle'),    qr/\AToggle\("c", isOn: \.constant\(true\)\)/, 'SwiftUI: toggle is a Toggle';
like $s->('toggleoff'), qr/isOn: \.constant\(false\)/,           'SwiftUI: a 0 value is off';
like $s->('multiline'), qr/\ATextEditor\(/,                      'SwiftUI: multiline is a TextEditor';
like $s->('number'),    qr/keyboardType\(\.decimalPad\)/,        'SwiftUI: number asks for a number pad';
like $s->('hidden'),    qr/\AEmptyView\(\)/,                     'SwiftUI: hidden draws nothing';
like $s->('text'),      qr/\ATextField\("p"/,                    'SwiftUI: text is a TextField';
like $s->('unknown'),   qr/\ATextField\(/,                       'SwiftUI: an unlisted type is plain text';

like $c->('secure'),    qr/PasswordVisualTransformation/,        'Compose: secure hides the text';
like $c->('toggle'),    qr/\ASwitch\(checked = true/,            'Compose: toggle is a Switch';
like $c->('multiline'), qr/minLines = 6/,                        'Compose: multiline takes its line count';
like $c->('number'),    qr/KeyboardType\.Number/,                'Compose: number asks for a number keyboard';
like $c->('hidden'),    qr/\AUnit \/\/ hidden/,                  'Compose: hidden draws nothing';
unlike $c->('text'),    qr/PasswordVisual|minLines|Switch/,      'Compose: text is a bare TextField';

my $fa = A(method => 'post', action => '/x');
is $swift->_cont('form', '', ' ', $fa)->{head}, 'Form',                    'SwiftUI: form is a Form';
like $swift->_cont('form', '', ' ', $fa)->{post}, qr/\.onSubmit \{ axaSubmit\(method: "post", action: "\/x"\) \}/,
    'SwiftUI: a form submits to its action';
like $comp->_cont('form', '', ' ', $fa)->{head}, qr/\AAxaForm\(method = "post", action = "\/x"\)/,
    'Compose: a form submits to its action';
my $sw = A(for => 'live-lane', mode => 'append');
like $swift->_cont('swap', '', ' ', $sw)->{head}, qr/\AAxaSwap\(target: "live-lane", mode: "append"\)/,
    'SwiftUI: a swap is applied to its target, not drawn in place';
like $comp->_cont('swap', '', ' ', $sw)->{head},  qr/\AAxaSwap\(target = "live-lane", mode = "append"\)/,
    'Compose: a swap is applied to its target, not drawn in place';

# ── HTML ──
{
    package W;
    sub new { bless { o => '' }, shift }
    sub start_element { my ($s, $e) = @_; $s->{o} .= "<$e->{LocalName}" . join('', map { " $_->{LocalName}=\"$_->{Value}\"" } sort { $a->{LocalName} cmp $b->{LocalName} } values %{ $e->{Attributes} // {} }) . '>' }
    sub end_element   { $_[0]{o} .= "</$_[1]{LocalName}>" }
    sub characters    { $_[0]{o} .= $_[1]{Data} }
}
sub html ($a) { my $w = W->new; my $t = Amin::UI::Target::HTML->new; $t->open('field', $a, $w); $t->close('field', $w); $w->{o} }

like html($f{secure}),    qr/<input[^>]*type="password"/,   'HTML: secure is a password input';
like html($f{toggle}),    qr/<input[^>]*type="checkbox"/,   'HTML: toggle is a checkbox';
like html($f{hidden}),    qr/<input[^>]*type="hidden"/,     'HTML: hidden is a hidden input';
like html($f{number}),    qr/<input[^>]*type="number"/,     'HTML: number is a number input';
like html($f{multiline}), qr/<textarea[^>]*rows="6"[^>]*>a\nb<\/textarea>/, 'HTML: multiline is a textarea holding its value';
like html($f{text}),      qr/<input[^>]*type="text"/,       'HTML: no type is text';

done_testing;
