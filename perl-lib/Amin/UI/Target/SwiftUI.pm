package Amin::UI::Target::SwiftUI;

# The SwiftUI dialect of the ui: target contract (see Amin::UI::Target::Base).
# Selected by `--os=ios`.  A total map from the 38-kind ui: vocabulary to
# SwiftUI: `_cont` gives each container its head and block-close, `_leaf` gives
# each leaf its whole expression.  Nothing is buffered — the target emits each
# fragment as the element filters drive it.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::UI::Target::Base';

# The wire channel the ui: element filters publish SwiftUI fragments on.
sub channel ($self) { 'ui-swiftui' }

# A container kind → head, the separator before its first child, and the two
# block closes (had children / empty).  Defaults from Base cover the common
# "Expression { … }" shape; only `app` (which wraps the body in a View struct)
# overrides them.
sub _cont ($self, $k, $pad, $pad1, $a) {
    my $title   = $self->attr($a, 'title');
    my $spacing = $self->attr($a, 'spacing');
    my $sp      = length $spacing ? ", spacing: $spacing" : '';

    return { head        => "$pad" . "struct " . $self->ident($title) . "View: View {\n"
                           . "$pad1" . "var body: some View {\n",
             first       => '',
             close_had   => "\n$pad1}\n$pad}",
             close_empty => "\n$pad1}\n$pad}" }
                                                       if $k eq 'app';
    return { head => "$pad" . "WindowGroup" }          if $k eq 'scene';
    return { head => "$pad" . "List" }                 if $k eq 'list';
    return { head => "$pad" . "ZStack" }               if $k eq 'stack';
    return { head => "$pad" . "HStack" }               if $k eq 'item';
    return { head => "$pad" . ($spacing ? "VStack(spacing: $spacing)" : "VStack") }
                                                       if $k eq 'vstack';
    return { head => "$pad" . ($spacing ? "HStack(spacing: $spacing)" : "HStack") }
                                                       if $k eq 'hstack';
    return { head => "$pad" . "VStack(alignment: .leading$sp)" } if $k eq 'column';
    return { head => "$pad" . "HStack(alignment: .center$sp)" }  if $k eq 'row';
    return { head => "$pad" . "LazyVGrid(columns: [GridItem(.adaptive(minimum: 120))]$sp)" }
                                                       if $k eq 'grid';
    return { head => "$pad" . "Section(header: Text(" . $self->lit($title) . "))" }
                                                       if $k eq 'section';
    return { head => "$pad" . "VStack(alignment: .leading, spacing: 8)",
             post => "\n$pad1.padding()" }             if $k eq 'card';
    return { head => "$pad" . "Button(" . $self->lit($title) . ")" }       if $k eq 'button';
    return { head => "$pad" . "NavigationLink(" . $self->lit($title) . ")" } if $k eq 'navigate';
    return { head => "$pad" . ".toolbar" }             if $k eq 'toolbar';
    return { head => "$pad" . ".sheet(isPresented: \$showSheet)" } if $k eq 'sheet';
    return { head => "$pad" . ".alert(" . $self->lit($title) . ", isPresented: \$showAlert)" }
                                                       if $k eq 'alert';
    # a form submits to its action: the runtime's axaSubmit is the intent
    return { head => "$pad" . "Form",
             post => "\n$pad1" . ".onSubmit { axaSubmit(method: "
                     . $self->lit($self->attr($a, 'method') || 'get') . ", action: "
                     . $self->lit($self->attr($a, 'action')) . ") }" }  if $k eq 'form';
    return { head => "$pad" . "Picker(\"\", selection: .constant(0))" }
                                                       if $k eq 'select';
    return { head => "$pad" . "VStack" }               if $k eq 'table';
    return { head => "$pad" . "HStack" }               if $k eq 'tr';
    return { head => "$pad" . "Group" }                if $k eq 'cell';
    # a streaming update: its content is applied to the view with the target
    # id, not drawn where it sits (the runtime's AxaSwap does the applying)
    return { head => "$pad" . "AxaSwap(target: " . $self->lit($self->attr($a, 'for'))
                     . ", mode: " . $self->lit($self->attr($a, 'mode') || 'replace') . ")" }
                                                       if $k eq 'swap';
    # the neutral AV container: a native player view owns its transport and
    # meter children, the same way the HTML target's runtime does
    return { head => "$pad" . "VStack(alignment: .leading, spacing: 10)",
             post => "\n$pad1" . ".padding(12)\n$pad1"
                     . ".background(.quaternary, in: RoundedRectangle(cornerRadius: 12))" }
                                                       if $k eq 'player';
    return undef;
}

# ui:field by semantic type (Base::field_type): each is the native control.
sub _field ($self, $a) {
    my $type  = $self->field_type($a);
    my $name  = $self->attr($a, 'name');
    my $ph    = $self->attr($a, 'placeholder');
    my $label = $self->lit(length $ph ? $ph : $name);
    my $val   = $self->lit($self->attr($a, 'value'));
    return "EmptyView() // hidden field " . $self->lit($name)   if $type eq 'hidden';
    return "SecureField($label, text: .constant($val))"         if $type eq 'secure';
    return "Toggle($label, isOn: .constant("
         . ($self->truthy($self->attr($a, 'value')) ? 'true' : 'false') . "))" if $type eq 'toggle';
    return "TextField($label, text: .constant($val)).keyboardType(.decimalPad)" if $type eq 'number';
    return "TextEditor(text: .constant($val))"                  if $type eq 'multiline';
    return "TextField($label, text: .constant($val))";
}

# A leaf kind → its whole expression.  The unreachable stub keeps a new `ui:`
# kind added to the codec without a projection visible.
sub _leaf ($self, $k, $pad, $a, $text) {
    my $title  = $self->attr($a, 'title');
    my $url    = $self->attr($a, 'url');
    my $points = $self->attr($a, 'points');
    my $src    = length $self->attr($a, 'src') ? $self->attr($a, 'src') : $title;
    my $parent = $self->stack->[-1];
    my $in_player = ($parent && ($parent->{kind} // '') eq 'player') ? 1 : 0;

    return $pad . "Text(" . $self->lit($text) . ")"            if $k eq 'text';
    return $pad . "Text(" . $self->lit($text) . ") /* ui:markdown */"
                                                               if $k eq 'markdown';
    return $pad . "Label(" . $self->lit($title) . ", systemImage: \"tag\")" if $k eq 'label';
    return $pad . "ProgressView()"                             if $k eq 'progress';
    return $pad . "Image(" . $self->lit($title) . ").resizable()" if $k eq 'image';
    return $pad . "AsyncImage(url: URL(string: " . $self->lit($url) . ")!)"
                                                               if $k eq 'asyncimage';
    # inside ui:player the transport is the native player's own control
    return $pad . "AxaAudioTransport(url: URL(string: " . $self->lit($src) . ")!)"
                                                               if $k eq 'audio' && $in_player;
    return $pad . "Text(" . $self->lit($src) . ") // ui:audio"
                                                               if $k eq 'audio';
    return $pad . "AxaEqualizer(bars: " . $self->eq_bars($a)
                 . ", mode: " . $self->lit($self->eq_mode($a)) . ")"
                                                               if $k eq 'equalizer';
    return $pad . "AxaVisualizer(mode: " . $self->lit($self->vis_mode($a)) . ")"
                                                               if $k eq 'visualizer';
    return $pad . "SparklineView(values: $points)"             if $k eq 'sparkline';
    return $pad . ".searchable(text: \$query)"                 if $k eq 'searchable';
    return $pad . "Text(" . $self->lit($text) . ").badge(" . (length $points ? $points : 1) . ")"
                                                               if $k eq 'badge';
    return $pad . $self->_field($a)                            if $k eq 'field';
    return $pad . "Text(" . $self->lit($text) . ")"            if $k eq 'option';
    return $pad . "/* ui:style */"                             if $k eq 'style';
    return $pad . "EmptyView() /* ui:$k unimplemented */";
}

1;
