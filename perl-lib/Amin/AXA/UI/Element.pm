package Amin::AXA::UI::Element;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AXA::UI::Base';
use Amin::AXA::UI::Base ();

# One app element, one filter.  machine_spec.xml declares a subclass with
# element= and namespace=; the gate splices an instance in while that element
# flows.  The element is consumed and replaced by what render() writes.  The
# element's own attributes are all the input the request gives it.

sub start_element ($self, $e) {
    if (!$self->{_depth} && $self->_is_mine($e)) {
        $self->{_depth} = 1;
        my %a = $self->_attrs($e);
        $self->{_csrf} = $a{csrf} // '';
        $self->render(\%a);
        return;
    }
    if ($self->{_depth}) { $self->{_depth}++; return }
    return $self->SUPER::start_element($e);
}

sub end_element ($self, $e) {
    if ($self->{_depth}) { $self->{_depth}--; return }
    return $self->SUPER::end_element($e);
}

sub characters ($self, $c) {
    return if $self->{_depth};
    return $self->SUPER::characters($c);
}

sub _is_mine ($self, $e) {
    return 0 unless ($e->{NamespaceURI} // '') eq $self->app_ns;
    my $want = $self->Element // return 0;
    return ($e->{LocalName} // '') eq $want ? 1 : 0;
}

sub _attrs ($self, $e) {
    my %a;
    for my $at (values %{ $e->{Attributes} // {} }) {
        my $n = $at->{LocalName} // $at->{Name} // '';
        $a{$n} = $at->{Value} // '' if length $n;
    }
    return %a;
}

sub render ($self, $a) { die ref($self) . ": render() not implemented\n" }

1;
