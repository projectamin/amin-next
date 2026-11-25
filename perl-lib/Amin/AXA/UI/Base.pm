package Amin::AXA::UI::Base;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'XML::SAX::Base';
use Class::Tiny qw(Handler Log Mode Name Element);
use Exporter 'import';

our @EXPORT_OK = qw(_short _clip _p UI_NS);

# Emit helpers shared by every AXA app filter.  A filter writes ui: IR (and its
# own app's elements, for composition) into $self->Handler.  Nothing here knows
# what the app is: a subclass says which namespace its elements live in by
# defining app_ns() (and app_prefix(), default 'app').  The only transport
# vocabulary is the form-field names the AXA FormCodec reads (axa.action,
# axa.csrf, axa.param.*), kept in _p/_form so another transport touches those
# and nothing else.

use constant UI_NS => 'http://projectamin.org/ns/ui/1';

sub _attrs_of (%a) {
    return { map {
        ; "{}$_" => { Name => $_, LocalName => $_, Prefix => '', NamespaceURI => '',
                      Value => defined $a{$_} ? "$a{$_}" : '' }
    } keys %a };
}

sub _ui_start ($self, $ln, %a) {
    my $h = $self->Handler or return;
    $h->start_element({ NamespaceURI => UI_NS, LocalName => $ln, Name => "ui:$ln",
                        Prefix => 'ui', Attributes => _attrs_of(%a) });
    return;
}
sub _ui_end ($self, $ln) {
    my $h = $self->Handler or return;
    $h->end_element({ NamespaceURI => UI_NS, LocalName => $ln, Name => "ui:$ln",
                      Prefix => 'ui', Attributes => {} });
    return;
}
sub _ui_void ($self, $ln, %a) { $self->_ui_start($ln, %a); $self->_ui_end($ln); return }
sub _ui_text ($self, $t) { my $h = $self->Handler or return; $h->characters({ Data => "$t" }); return }

sub app_ns     ($self) { '' }
sub app_prefix ($self) { 'app' }

# One of the app's own elements written into the stream; the gate downstream
# splices the filter the machine spec declares for it.
sub _app ($self, $ln, %a) {
    my $h = $self->Handler or return;
    my ($ns, $px) = ($self->app_ns, $self->app_prefix);
    $h->start_element({ NamespaceURI => $ns, LocalName => $ln, Name => "$px:$ln",
                        Prefix => $px, Attributes => _attrs_of(%a) });
    $h->end_element({ NamespaceURI => $ns, LocalName => $ln, Name => "$px:$ln",
                      Prefix => $px, Attributes => {} });
    return;
}

sub _leaf ($self, $kind, $t, %a) {
    $self->_ui_start($kind, %a);
    $self->_ui_text($t // '');
    $self->_ui_end($kind);
    return;
}
sub _text     ($self, $t) { $self->_leaf('text', $t) }
sub _label    ($self, $t) { $self->_leaf('label', $t) }
sub _badge    ($self, $t = '') { $self->_leaf('badge', $t) }
sub _markdown ($self, $t) { $self->_leaf('markdown', $t) }
sub _alert    ($self, $t) { return unless defined $t && length $t; $self->_leaf('alert', $t) }
sub _button   ($self, $title) { $self->_ui_void('button', title => $title) }
sub _link     ($self, $t, $to) { $self->_ui_void('navigate', to => $to, title => $t) }

sub _audio ($self, $src, $title = '') {
    return unless defined $src && length $src;
    $self->_ui_void('audio', src => $src, title => _short($title, 80));
    return;
}

# The neutral AV construct: a player container holding its transport and a
# meter.  What that becomes is the render target's business (HTML owns a Web
# Audio runtime; the native targets emit player and bar views), so an app
# states the intent once and no app code knows the platform.
sub _player ($self, $src, $title = '', %o) {
    return unless defined $src && length $src;
    $self->_ui_start('player', title => _short($title, 80));
    $self->_audio($src, $title);
    $self->_ui_void('equalizer',
        bars => ($o{bars} // 32),
        mode => ($o{mode} // 'bars'));
    $self->_ui_end('player');
    return;
}

sub _swap ($self, $mode, $for, $body) {
    $self->_ui_start('swap', for => $for, mode => $mode);
    $body->();
    $self->_ui_end('swap');
    return;
}

sub _flash ($self, $notice, $err) {
    $self->_alert($err) if defined $err && length $err;
    $self->_text($notice) if defined $notice && length $notice;
    return;
}

# type: text | password | checkbox | number | multiline (lines=N)
sub _field ($self, $name, $value = '', %o) {
    my %at = ( type => $o{type} // 'text', name => $name, value => $value // '' );
    $at{$_} = $o{$_} for grep { defined $o{$_} } qw(placeholder lines min max);
    $self->_ui_void('field', %at);
    return;
}

sub _row ($self, $label, $name, $value, %o) {
    $self->_ui_start('vstack');
    $self->_label($label);
    $self->_field($name, $value, %o);
    $self->_ui_end('vstack');
    return;
}

# A picker posting one value.  $choices is [ [value, label], … ]; $value is the
# current selection.  The option's text is its label.
sub _select ($self, $name, $value, $choices, %o) {
    my %at = (name => $name);
    $at{$_} = $o{$_} for grep { defined $o{$_} } qw(id);
    $self->_ui_start('select', %at);
    for my $c (@$choices) {
        my ($v, $label) = @$c;
        $self->_ui_start('option', value => $v,
            defined $value && length $value && "$value" eq "$v" ? (selected => '1') : ());
        $self->_ui_text($label);
        $self->_ui_end('option');
    }
    $self->_ui_end('select');
    return;
}

sub _csrf ($self) { $self->{_csrf} // '' }
sub _p ($name) { 'axa.param.' . $name }

sub _hidden ($self, $name, $value) {
    $self->_ui_void('field', type => 'hidden', name => $name, value => $value // '');
}

sub _form ($self, $action, $body, $to = '/') {
    $self->_ui_start('form', method => 'post', action => $to);
    $self->_hidden('axa.action', $action);
    $self->_hidden('axa.csrf', $self->_csrf);
    $body->();
    $self->_ui_end('form');
    return;
}

# Navigation is a GET: same DOM as a button form, but it is a route.
sub _get_form ($self, $action, $body, %query) {
    $self->_ui_start('form', method => 'get', action => $action);
    $self->_hidden($_, $query{$_}) for sort keys %query;
    $body->();
    $self->_ui_end('form');
    return;
}

sub _short ($s, $n) {
    $s //= '';
    $s =~ s/\s+/ /g;
    return $s if length($s) <= $n;
    return substr($s, 0, $n - 1) . '...';
}

sub _clip ($s, $n) {
    $s //= '';
    return length($s) <= $n ? $s : substr($s, 0, $n) . "\n…";
}

1;
