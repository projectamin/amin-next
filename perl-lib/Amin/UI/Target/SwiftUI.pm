package Amin::UI::Target::SwiftUI;

# The SwiftUI dialect of the ui: target contract (see Amin::UI::Target::Base).
# Selected by `--os=ios`.  A total map from the 25-kind ui: vocabulary to
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
    return undef;
}

# A leaf kind → its whole expression.  The unreachable stub keeps a new `ui:`
# kind added to the codec without a projection visible.
sub _leaf ($self, $k, $pad, $a, $text) {
    my $title  = $self->attr($a, 'title');
    my $url    = $self->attr($a, 'url');
    my $points = $self->attr($a, 'points');

    return $pad . "Text(" . $self->lit($text) . ")"            if $k eq 'text';
    return $pad . "Label(" . $self->lit($title) . ", systemImage: \"tag\")" if $k eq 'label';
    return $pad . "ProgressView()"                             if $k eq 'progress';
    return $pad . "Image(" . $self->lit($title) . ").resizable()" if $k eq 'image';
    return $pad . "AsyncImage(url: URL(string: " . $self->lit($url) . ")!)"
                                                               if $k eq 'asyncimage';
    return $pad . "SparklineView(values: $points)"             if $k eq 'sparkline';
    return $pad . ".searchable(text: \$query)"                 if $k eq 'searchable';
    return $pad . "Text(" . $self->lit($text) . ").badge(" . (length $points ? $points : 1) . ")"
                                                               if $k eq 'badge';
    return $pad . "EmptyView() /* ui:$k unimplemented */";
}

1;
