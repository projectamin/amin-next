package Amin::AI::Music::Page;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AXA::UI::Base';
use Amin::AI::Music::Store;

# The page filter: the app's one static (element-less) filter, at `middle`.
# Every event that is not its own <mu:request>, <mu:action> or <mu:result> is
# forwarded unchanged.  A request becomes the page skeleton: ui: layout plus mu:
# elements the machine spec declares, which the gate downstream expands.  The
# only elements that can run are the ones machine_spec.xml names.

use constant MU_NS => 'urn:projectamin:app:music';
sub app_ns     ($self) { MU_NS }
sub app_prefix ($self) { 'mu' }

sub start_element ($self, $e) {
    if (($e->{NamespaceURI} // '') eq MU_NS) {
        my $ln = $e->{LocalName} // '';
        if ($ln =~ /\A(?:request|action|result)\z/) {
            $self->{_swallow} = 1;
            my %a = map { (($_->{LocalName} // $_->{Name} // '') => ($_->{Value} // '')) }
                    values %{ $e->{Attributes} // {} };
            $self->{_csrf} = $a{csrf} // $self->{_csrf} // '';
            if    ($ln eq 'result')  { $self->{_result} = \%a }
            elsif ($ln eq 'action')  { $self->_action(\%a) }
            else                     { $self->_route(\%a) }
            return;
        }
    }
    return $self->SUPER::start_element($e);
}

sub end_element ($self, $e) {
    if ($self->{_swallow}) { $self->{_swallow}--; return }
    return $self->SUPER::end_element($e);
}

sub characters ($self, $c) {
    return if $self->{_swallow};
    return $self->SUPER::characters($c);
}

sub _route ($self, $a) {
    my $r = delete $self->{_result} // {};
    my ($notice, $err);
    if (%$r) { $r->{ok} ? ($notice = $r->{notice}) : ($err = $r->{err} // 'Action failed.') }
    my $panel = length($r->{panel} // '') ? $r->{panel} : ($a->{panel} // '');
    my %draft = map { $_ => ($a->{$_} // '') } qw(style prompt lyrics duration instrumental provider model);
    # reuse: a take's inputs go back into the form (and its model if still known)
    if (length($a->{take} // '') && (my $t = Amin::AI::Music::Store->take($a->{take}))) {
        @draft{qw(style prompt lyrics)} = @$t{qw(style prompt lyrics)};
        $draft{model} = $t->{model} // '';
    }
    $self->_page($notice, $err, $panel eq 'settings' ? 'settings' : '', \%draft);
    return;
}

# A take is painted, not awaited: the page goes out at once with a live lane
# whose mu:make paints progress into it as swaps while the hop runs.
sub _action ($self, $a) {
    my $op = $a->{op} // '';
    if ($op eq 'music.make') {
        $self->_page(undef, undef, '', { map { $_ => ($a->{$_} // '') } qw(style prompt lyrics duration instrumental model) }, $a);
    }
    else {
        $self->_page(undef, "Unknown action '$op'.", '', {});
    }
    return;
}

sub _page ($self, $notice, $err, $panel, $draft, $live = undef) {
    my %ctx = ( csrf => $self->_csrf );
    $self->_ui_start('app', title => 'music', theme => 'soft-studio');
    $self->_app('header');
    $self->_ui_start('scene');
    $self->_ui_start('column');
    $self->_flash($notice, $err);
    $self->_app('settings', %ctx, provider => ($draft->{provider} // '')) if $panel eq 'settings';
    $self->_app('composer', %ctx,
        map { $_ => ($draft->{$_} // '') } qw(style prompt lyrics duration model));
    $self->_ui_start('vstack', id => 'live-lane');
    $self->_app('make', %ctx, map { $_ => ($live->{$_} // '') } qw(style prompt lyrics duration instrumental model)) if $live;
    $self->_ui_end('vstack');
    $self->_app('library');
    $self->_ui_end('column');
    $self->_ui_end('scene');
    $self->_ui_end('app');
    return;
}

1;
