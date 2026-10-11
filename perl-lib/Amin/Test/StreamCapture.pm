package Amin::Test::StreamCapture;

# Amin::Test::StreamCapture — drops in as any Handler and records all
# method invocations (name + args) into a filter-local array so the test
# can post-hoc inspect the stream without re-parsing rendered output.
#
# General-purpose replacement for inline AUTOLOAD Capture blobs such as the
# historical one in t/06-cond-os.t:
#
#   { package Capture; sub new { bless[], shift }
#     sub AUTOLOAD { my $m = our $AUTOLOAD; $m =~ s/.*:://; return if $m eq 'DESTROY';
#                    my ($s, @a) = @_; push @$s, [$m, @a]; return wantarray ? () : undef } }
#
# Example:
#
#   my $cap = Amin::Test::StreamCapture->new;
#   my $c = Amin::Cond::OS->new(Handler => $cap, Log => $log);
#   $c->start_element(...);
#   my @events = $cap->captured->@*;
#   is scalar(@events), 4, '4 events forwarded';
#
use v5.38; use warnings; use utf8; use experimental 'signatures';
use Class::Tiny qw(captured drop_after_closed),
    { captured => sub { [] } };

sub push_event ($self, $name, @args) {
    push $self->captured->@*, [$name, @args];
    return wantarray ? () : undef;
}

sub AUTOLOAD ($self, @a) {
    my $m = our $AUTOLOAD;
    $m =~ s/.*:://;
    return if $m eq 'DESTROY';
    return $self->push_event($m, @a);
}

sub start_document ($self, @a) { $self->push_event('start_document', @a) }
sub end_document   ($self, @a) { $self->push_event('end_document',   @a) }
sub start_element  ($self, @a) { $self->push_event('start_element',  @a) }
sub end_element    ($self, @a) { $self->push_event('end_element',    @a) }
sub characters     ($self, @a) { $self->push_event('characters',     @a) }
sub processing_instruction ($self, @a) { $self->push_event('pi', @a) }
sub comment        ($self, @a) { $self->push_event('comment', @a) }
sub ignorable_whitespace  ($self, @a) { $self->push_event('ignorable_whitespace', @a) }

1;
