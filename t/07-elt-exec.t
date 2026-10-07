#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Elt;
use Amin::Handler::Writer;
use Amin::Log::Standard;
use Amin qw(NS);

{
    package # hide
        Amin::Command::StubEcho;
    use v5.38; use warnings; use experimental 'signatures';
    use parent -norequire => 'Amin::Elt';
    sub name    { 'stub_echo' }
    sub element { 'command'   }
    sub build_argv ($self) {
        ('echo', 'HELLO', $self->{params}[0] // 'PARAM0')
    }
}

sub capture_output ($mode = 'dryrun') {
    my $w   = Amin::Handler::Writer->new(indent => 0);
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $elt = Amin::Command::StubEcho->new(
        Handler => $w, Log => $log, Mode => $mode,
        params  => ['ARG1']);
    $elt->execute;
    ($w->output, $w, $elt, $log);
}

my ($out) = capture_output('dryrun');
like($out, qr{<amin:result[^>]*amin:kind="dryrun"},
     'dryrun emits <result kind=dryrun>');
like($out, qr{<amin:stream amin:channel="argv">},
     'dryrun has argv stream event');
like($out, qr{echo.*HELLO.*ARG1},
     'dryrun argv stream has assembled command (ONE place only)');
my @matches = ($out =~ /echo[^\n]*HELLO[^\n]*ARG1/g);
is(scalar @matches, 1,
   'dryrun: assembled command string appears exactly ONCE (no duplication)');
like($out, qr{<amin:status[^>]*amin:kind="dryrun"[^>]*>\s*</amin:status>},
     'dryrun: <status> is content-free (pure metadata attrs, no duplicated argv text)');
unlike($out, qr{amin:channel="out"},
       'dryrun: never spawns processes, so no stdout/stderr streams exist');

my ($out_render) = capture_output('render');
like($out_render, qr{amin:kind="dryrun"}, 'render uses no-exec branch');
unlike($out_render, qr{amin:channel="out"}, 'render also has no stdout streams');

my ($out_run, $w_run, $elt_run) = capture_output('run');
like($out_run, qr{<amin:result[^>]*amin:kind="running"},
     'run opens result with kind=running BEFORE exec completed');
like($out_run, qr{<amin:stream amin:channel="out">\s*HELLO\s+ARG1\s*</amin:stream>},
     'run: channel=out stream contains actual child output line');
my $final_status = ($out_run =~ m{<amin:status\b([^>]*?)>}g)[-1];
like($final_status, qr{amin:kind="success"},   'status metadata: kind=success');
like($final_status, qr{amin:rc="0"},             'status metadata: rc=0');
like($final_status, qr{amin:duration="[0-9]+\.[0-9]+"},
     'status metadata: duration present (float seconds)');
like($final_status, qr{amin:exit_kind="ok"},    'status metadata: exit_kind=ok');
like($final_status, qr{amin:pid="[0-9]+"},      'status metadata: pid populated');

like($out_run, qr{<amin:status\b[^>]*>\s*</amin:status>},
     'run: status element has no non-whitespace content (no duplicated argv/out text)');
unlike($out_run, qr{channel="out_summary"}, 'run: no out_summary (UI concatenates per-line out itself)');
unlike($out_run, qr{channel="err_summary"}, 'run: no err_summary');

{
    package # hide
        Amin::Command::StubFalse;
    use v5.38; use warnings; use experimental 'signatures';
    use parent -norequire => 'Amin::Elt';
    sub name    { 'stub_false' }
    sub element { 'command'   }
    sub build_argv { ('false') }
}
my $w_fail = Amin::Handler::Writer->new;
my $e_fail = Amin::Command::StubFalse->new(Handler => $w_fail, Mode => 'run',
    Log => Amin::Log::Standard->new(stderr=>0));
$e_fail->execute;
my $o_fail = $w_fail->output;
like($o_fail, qr{amin:kind="error"},      'nonzero rc → status kind=error');
like($o_fail, qr{amin:exit_kind="nonzero"}, 'nonzero rc → exit_kind=nonzero');
like($o_fail, qr{amin:rc="1"},              'nonzero rc → rc attr numeric');

done_testing;
