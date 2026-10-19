package Amin::AXA::FormCodec;
use v5.38; use warnings; use utf8;
use Class::Tiny;

# FormCodec turns request data into the app's OWN declared fragment (plan
# §4.2): dumb {placeholder} substitution, nothing else.  No policy, no
# domain knowledge — it cannot emit anything the bundle does not already
# contain, because every byte outside a substituted value comes from the
# fragment the bundle declared in axa.xml.  Encodings are not dialects.
#
# Values are XML-escaped on substitution: the fragment is attribute content
# in the app's dialect, and escaping here keeps Handler::HTML the single
# point of escaping for *output* while keeping input data inert.

sub inflate ($class, $fragment, $values) {
    $fragment =~ s/\{([A-Za-z0-9_.\-]+)\}/ _val($values, $1) /ge;
    return $fragment;
}

sub _val ($values, $key) {
    my $v = $values->{$key} // '';
    $v =~ s/([<>&"'])/ _esc($1) /ge;
    return $v;
}

sub _esc ($c) {
    { '<' => '&lt;', '>' => '&gt;', '&' => '&amp;',
      '"' => '&quot;', "'" => '&apos;' }->{$c};
}

1;
