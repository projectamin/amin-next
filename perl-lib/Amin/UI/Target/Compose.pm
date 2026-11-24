package Amin::UI::Target::Compose;

# The Jetpack Compose dialect of the ui: target contract (see
# Amin::UI::Target::Base).  Selected by `--os=android`.  The Compose twin of
# Amin::UI::Target::SwiftUI: same IR, same closed-world validation, same
# streaming verbs — only the projection differs, which keeps the two platforms
# provably in step (every ui: kind has a target in each).

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::UI::Target::Base';

# The wire channel the ui: element filters publish Compose fragments on.
sub channel ($self) { 'ui-compose' }

# A container kind → head, the separator before its first child, and the two
# block closes (had children / empty).  Base's defaults fit the common
# "Expression { … }" shape; `app`, `section`, `button`/`navigate` and `toolbar`
# are the Kotlin idioms that differ.
sub _cont ($self, $k, $pad, $pad1, $a) {
    my $title   = $self->attr($a, 'title');
    my $spacing = $self->attr($a, 'spacing');
    my ($varr, $harr) = (
        length $spacing ? "verticalArrangement = Arrangement.spacedBy($spacing.dp)"   : '',
        length $spacing ? "horizontalArrangement = Arrangement.spacedBy($spacing.dp)" : '',
    );
    my $title_l = $self->lit($title);

    return { head        => "$pad" . "\@Composable\n$pad" . "fun " . $self->ident($title) . "() {\n",
             first       => '',
             close_had   => "\n$pad}",
             close_empty => "\n$pad}" }                if $k eq 'app';
    return { head => "$pad" . "Surface" }              if $k eq 'scene';
    return { head => "$pad" . "LazyColumn" }           if $k eq 'list';
    return { head => "$pad" . "Box" }                  if $k eq 'stack';
    return { head => "$pad" . "Row" }                  if $k eq 'item';
    return { head => "$pad" . "Column" . ($varr ? "($varr)" : '') }
                                                       if $k eq 'vstack' || $k eq 'column';
    return { head => "$pad" . "Row" . ($harr ? "($harr)" : '') } if $k eq 'hstack';
    return { head => "$pad" . "Row("
             . join(', ', grep { length } ('verticalAlignment = Alignment.CenterVertically', $harr))
             . ")" }                                   if $k eq 'row';
    return { head => "$pad" . "LazyVerticalGrid(columns = GridCells.Adaptive(minSize = 120.dp)"
             . ($varr ? ", $varr" : '') . ")" }        if $k eq 'grid';
    return { head => "$pad" . "Card" }                 if $k eq 'card';
    return { head        => "$pad" . "Column {\n$pad1"
                           . "Text($title_l, style = MaterialTheme.typography.titleMedium)",
             first       => "\n",
             close_had   => "\n$pad}",
             close_empty => "\n$pad}" }                if $k eq 'section';
    return { head        => "$pad" . "Button(onClick = { })",
             first       => " {\n",
             close_had   => "\n$pad}",
             close_empty => " { Text($title_l) }" }    if $k eq 'button';
    return { head        => "$pad" . "TextButton(onClick = { })",
             first       => " {\n",
             close_had   => "\n$pad}",
             close_empty => " { Text($title_l) }" }    if $k eq 'navigate';
    return { head        => "$pad" . "TopAppBar(title = { Text($title_l) }",
             first       => ", actions = {\n",
             close_had   => "\n$pad})",
             close_empty => ")" }                      if $k eq 'toolbar';
    return { head => "$pad" . "ModalBottomSheet(onDismissRequest = { })" } if $k eq 'sheet';
    return { head => "$pad" . "AlertDialog(onDismissRequest = { })" }      if $k eq 'alert';
    # a form submits to its action: the runtime's AxaForm is the intent
    return { head => "$pad" . "AxaForm(method = " . $self->lit($self->attr($a, 'method') || 'get')
                     . ", action = " . $self->lit($self->attr($a, 'action')) . ")" }
                                                       if $k eq 'form';
    return { head => "$pad" . "Column" }               if $k eq 'select';
    return { head => "$pad" . "Column" }               if $k eq 'table';
    return { head => "$pad" . "Row" }                  if $k eq 'tr';
    return { head => "$pad" . "Box" }                  if $k eq 'cell';
    # a streaming update: its content is applied to the view with the target
    # id, not drawn where it sits (the runtime's AxaSwap does the applying)
    return { head => "$pad" . "AxaSwap(target = " . $self->lit($self->attr($a, 'for'))
                     . ", mode = " . $self->lit($self->attr($a, 'mode') || 'replace') . ")" }
                                                       if $k eq 'swap';
    return undef;
}

# ui:field by semantic type (Base::field_type): each is the native control.
sub _field ($self, $a) {
    my $type  = $self->field_type($a);
    my $name  = $self->attr($a, 'name');
    my $ph    = $self->attr($a, 'placeholder');
    my $label = "label = { Text(" . $self->lit(length $ph ? $ph : $name) . ") }";
    my $val   = $self->lit($self->attr($a, 'value'));
    my $base  = "value = $val, onValueChange = { }, $label";
    return "Unit // hidden field " . $self->lit($name)          if $type eq 'hidden';
    return "TextField($base, visualTransformation = PasswordVisualTransformation())"
                                                               if $type eq 'secure';
    return "Switch(checked = " . ($self->truthy($self->attr($a, 'value')) ? 'true' : 'false')
         . ", onCheckedChange = { })"                          if $type eq 'toggle';
    return "TextField($base, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))"
                                                               if $type eq 'number';
    if ($type eq 'multiline') {
        my $n = $self->attr($a, 'lines');
        return "TextField($base, minLines = " . ($n =~ /\A\d{1,2}\z/ && $n > 0 ? $n : 4) . ")";
    }
    return "TextField($base)";
}

# A leaf kind → its whole expression.  The unreachable stub keeps a new `ui:`
# kind added to the codec without a projection visible.
sub _leaf ($self, $k, $pad, $a, $text) {
    my $title  = $self->attr($a, 'title');
    my $url    = $self->attr($a, 'url');
    my $points = $self->attr($a, 'points');

    return $pad . "Text(" . $self->lit($text) . ")"            if $k eq 'text';
    return $pad . "Text(" . $self->lit($text) . ") // ui:markdown"
                                                               if $k eq 'markdown';
    return $pad . "Text(" . $self->lit($title) . ") // ui:label" if $k eq 'label';
    return $pad . "Badge { Text(" . $self->lit($text) . ") }"  if $k eq 'badge';
    return $pad . "CircularProgressIndicator()"                if $k eq 'progress';
    return $pad . "Image(painter = painterResource(" . $self->lit($title) . "), contentDescription = null)"
                                                               if $k eq 'image';
    return $pad . "AsyncImage(model = " . $self->lit($url) . ", contentDescription = null)"
                                                               if $k eq 'asyncimage';
    return $pad . "Text(" . $self->lit(length $self->attr($a, 'src') ? $self->attr($a, 'src') : $title)
                 . ") // ui:audio"                              if $k eq 'audio';
    return $pad . "Sparkline(points = $points)"                if $k eq 'sparkline';
    return $pad . "/* ui:searchable */"                        if $k eq 'searchable';
    return $pad . $self->_field($a)                            if $k eq 'field';
    return $pad . "Text(" . $self->lit($text) . ")"            if $k eq 'option';
    return $pad . "/* ui:style */"                             if $k eq 'style';
    return $pad . "/* ui:$k unimplemented */";
}

1;
