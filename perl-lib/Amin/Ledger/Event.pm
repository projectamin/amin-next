package Amin::Ledger::Event;
# Emit an audited `ledger:event` into a SAX stream.  Amin::Filter::Ledger turns
# it into a typed, per-actor-chained entry in the Amin ledger.
use v5.38; use warnings;
use Exporter 'import';
our @EXPORT_OK = qw(emit_event emit_authz emit_tool_call);

use constant LEDGER_NS => 'http://projectamin.org/ns/ledger/';

sub emit_event ($handler, %f) {
    die "emit_event: kind required\n" unless length($f{kind} // '');
    my %attrs;
    for my $k (keys %f) {
        next unless defined $f{$k};
        $attrs{"{}$k"} = { Name => $k, LocalName => $k, Prefix => '', NamespaceURI => '', Value => "$f{$k}" };
    }
    my %el = (NamespaceURI => LEDGER_NS, LocalName => 'event', Name => 'ledger:event', Prefix => 'ledger');
    $handler->start_element({ %el, Attributes => \%attrs });
    $handler->end_element({ %el });
    return;
}

# Authorisation decision: grant|deny of an action by an actor under a capability.
sub emit_authz ($handler, %a) {
    my $d = $a{decision} // '';
    die "emit_authz: decision must be grant or deny\n" unless $d eq 'grant' || $d eq 'deny';
    return emit_event($handler, kind => "authz.$d", actor => $a{actor}, subject => $a{action},
        auth => $a{auth}, (map { defined $a{$_} ? ($_ => $a{$_}) : () } qw(resource reason)));
}

# AI agent tool call (before it runs, so the intent is on the record).
sub emit_tool_call ($handler, %a) {
    return emit_event($handler, kind => 'ai.tool_call', actor => $a{agent}, subject => $a{tool},
        auth => $a{auth}, (map { defined $a{$_} ? ($_ => $a{$_}) : () } qw(args_hash model session)));
}

1;
