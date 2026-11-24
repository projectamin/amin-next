package Amin::AXA::UI::Effect;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AXA::UI::Element';

# An app element that does something.  It runs at `begin`, performs its one
# mutation, and is replaced in the stream by <app:result/> saying what happened;
# the page filter downstream reads that.  A subclass defines
# apply($self, \%attrs) -> { ok, notice } | { err } and may name the panel to
# reopen on failure.

sub render ($self, $a) {
    my $res = eval { $self->apply($a) };
    if (!$res) {
        (my $why = $@ // 'unknown error') =~ s/\s+\z//;
        $res = { err => "Action failed: $why" };
    }
    $self->_app('result', $res->{ok}
        ? ( ok => 1, notice => $res->{notice} // '' )
        : ( ok => 0, err => $res->{err} // 'Action failed.', panel => $self->panel_on_error // '' ));
    return;
}

sub panel_on_error ($self) { '' }

1;
