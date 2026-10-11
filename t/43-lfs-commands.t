#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

require Amin::Command::Pass;
require Amin::Command::Cp;
require Amin::Command::Tar;
require Amin::Command::Gcc;
require Amin::Command::Gxx;
require Amin::Command::Make;
require Amin::Command::Sed;
require Amin::Command::Wget;
require Amin::Command::Chmod;
require Amin::Command::Bash;
require Amin::Command::Mount;
require Amin::Command::Dd;
require Amin::Command::True;
require Amin::Command::Pwd;
require Amin::Log::Standard;
require Amin::Test::StreamCapture;

my $NS = 'http://projectamin.org/ns/2026/';

sub el ($ln, %attrs) {
    my $a = {};
    while (my ($k, $v) = each %attrs) {
        $a->{"{}$k"} = {
            Name => $k, LocalName => $k, Prefix => 'amin',
            NamespaceURI => $NS, Value => "$v",
        };
    }
    +{ NamespaceURI => $NS, LocalName => $ln, Name => "amin:$ln",
       Prefix => 'amin', Attributes => $a };
}

# ── Amin::Test pattern: run a command filter with StreamCapture as Handler,
#    feed real SAX events (no direct {params}/{flags} manipulation), then
#    assert on the captured event stream.
sub run_command ($class, $name, $mode, @children) {
    my $cap = Amin::Test::StreamCapture->new;
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $c   = $class->new(Handler => $cap, Log => $log, Mode => $mode);
    $c->start_element(el('command', name => $name));
    for my $ch (@children) {
        my ($type, $cname, $value) = @$ch;
        $c->start_element(el($type, name => $cname));
        $c->characters({ Data => $value }) if defined $value && length $value;
        $c->end_element(el($type));
    }
    $c->end_element(el('command'));
    return $cap;
}

# Extract the text of a specific <amin:stream channel="..."> from captured events.
sub stream_text ($cap, $channel) {
    my $in = 0;
    my $text = '';
    for my $ev ($cap->captured->@*) {
        my ($m, @a) = @$ev;
        if ($m eq 'start_element') {
            my $e = $a[0];
            if (($e->{LocalName} // '') eq 'stream') {
                my $ch = $e->{Attributes}{'{}channel'};
                $in = ($ch && $ch->{Value} eq $channel) ? 1 : 0;
            }
        } elsif ($m eq 'characters' && $in) {
            $text .= $a[0]{Data} // '';
        } elsif ($m eq 'end_element') {
            $in = 0 if ($a[0]{LocalName} // '') eq 'stream';
        }
    }
    return $text;
}

# Return the attrs of the first <amin:status> element seen.
sub status_attrs ($cap) {
    for my $ev ($cap->captured->@*) {
        my ($m, @a) = @$ev;
        next unless $m eq 'start_element';
        my $e = $a[0];
        next unless ($e->{LocalName} // '') eq 'status';
        my %h;
        while (my ($k, $v) = each %{ $e->{Attributes} // {} }) {
            $h{$v->{LocalName}} = $v->{Value};
        }
        return \%h;
    }
    return {};
}

sub result_kind ($cap) {
    for my $ev ($cap->captured->@*) {
        my ($m, @a) = @$ev;
        next unless $m eq 'start_element';
        my $e = $a[0];
        next unless ($e->{LocalName} // '') eq 'result';
        my $k = $e->{Attributes}{'{}kind'};
        return $k ? $k->{Value} : '';
    }
    return '';
}

# ── Contract: every LFS command is an EXPLICIT filter with a specific name ──
is(Amin::Command::Cp->name,    'cp',    'Cp contract: name = cp');
is(Amin::Command::Tar->name,   'tar',   'Tar contract: name = tar');
is(Amin::Command::Gcc->name,   'gcc',   'Gcc contract: name = gcc');
is(Amin::Command::Gxx->name,   'g++',   'Gxx contract: name = g++ (plus sign preserved)');
is(Amin::Command::Make->name,  'make',  'Make contract: name = make');
is(Amin::Command::Sed->name,   'sed',   'Sed contract: name = sed');
is(Amin::Command::Wget->name,  'wget',  'Wget contract: name = wget');
is(Amin::Command::Chmod->name, 'chmod', 'Chmod contract: name = chmod');
is(Amin::Command::Bash->name,  'bash',  'Bash contract: name = bash');
is(Amin::Command::Mount->name, 'mount', 'Mount contract: name = mount');
is(Amin::Command::Dd->name,    'dd',    'Dd contract: name = dd');
is(Amin::Command::True->name,  'true',  'True contract: name = true');
is(Amin::Command::Cp->element, 'command', 'all LFS commands bind element=command');

# ── Contract: each command defines its OWN build_argv (not inherited from Pass) ──
for my $pkg (qw(Cp Tar Gcc Gxx Make Sed Wget Chmod Bash Mount Dd True Pwd)) {
    my $class = "Amin::Command::$pkg";
    my $code  = $class->can('build_argv');
    my $pass  = Amin::Command::Pass->can('build_argv');
    isnt($code, $pass, "$pkg has its own build_argv (not inherited from Pass)");
}

# ── Closed-world flag allowlist via SAX feed (Amin::Test::StreamCapture) ──
{
    my $cap = run_command('Amin::Command::Cp', 'cp', 'dryrun',
        [flag  => 'r'],
        [flag  => 'f'],
        [flag  => 'preserve', 'timestamps'],
        [flag  => 'evil-inject', 'rm -rf /'],
        [param => 'src', '/etc/hosts'],
        [param => 'dst', '/tmp/hosts.bak']);
    is(result_kind($cap), 'dryrun', 'Cp dryrun: result kind = dryrun');
    like(stream_text($cap, 'argv'), qr{^cp\b},         'Cp argv starts with cp');
    like(stream_text($cap, 'argv'), qr{\s-rf\b},         'Cp argv: short booleans concatenated -rf');
    like(stream_text($cap, 'argv'), qr{--preserve=timestamps}, 'Cp argv: long flag with value');
    like(stream_text($cap, 'argv'), qr{/etc/hosts},      'Cp argv: src param passed');
    like(stream_text($cap, 'argv'), qr{/tmp/hosts.bak},  'Cp argv: dst param passed');
    unlike(stream_text($cap, 'argv'), qr{evil-inject},   'Cp: unsupported evil-inject flag DROPPED (closed-world)');
    unlike(stream_text($cap, 'argv'), qr{rm -rf},        'Cp: injection payload never reaches argv');
}

# Tar: targets structure, short boolean flags concatenate -xfJ
{
    my $cap = run_command('Amin::Command::Tar', 'tar', 'dryrun',
        [flag  => 'x'],
        [flag  => 'f'],
        [flag  => 'J'],
        [param => 'target', 'gcc-13.2.0.tar.xz']);
    like(stream_text($cap, 'argv'), qr{^tar\s+-xfJ\s+gcc-13\.2\.0\.tar\.xz},
        'Tar: targets + short boolean flags concatenate -xfJ');
}

# Gcc: in_only, output via -o flag; unsupported wall dropped
{
    my $cap = run_command('Amin::Command::Gcc', 'gcc', 'dryrun',
        [flag  => 'O', '2'],
        [flag  => 'std', 'c17'],
        [flag  => 'g'],
        [flag  => 'wall'],
        [flag  => 'o', 'hello'],
        [param => 'in', 'hello.c']);
    my $argv = stream_text($cap, 'argv');
    like($argv, qr{^gcc\b},                      'Gcc argv starts with gcc');
    like($argv, qr{-g},                          'Gcc: short boolean -g passes');
    like($argv, qr{-O2},                         'Gcc: short valued -O2 passes');
    like($argv, qr{-ohello},                     'Gcc: short valued -ohello passes');
    like($argv, qr{--std=c17},                   'Gcc: long valued --std=c17 passes');
    like($argv, qr{hello\.c},                    'Gcc: in param passed');
    unlike($argv, qr{wall},                      'Gcc: unsupported wall flag DROPPED');
}

# Gxx: in_only, command name g++ preserved
{
    my $cap = run_command('Amin::Command::Gxx', 'g++', 'dryrun',
        [flag  => 'std', 'c++20'],
        [flag  => 'o', 'prog'],
        [param => 'in', 'main.cpp']);
    my $argv = stream_text($cap, 'argv');
    like($argv, qr{^g\+\+\s},                    'Gxx: command name g++ preserved');
    like($argv, qr{-oprog},                      'Gxx: short valued -oprog');
    like($argv, qr{--std=c\+\+20},               'Gxx: long valued --std=c++20');
    like($argv, qr{main\.cpp},                   'Gxx: in param passed');
}

# Wget: url structure, supported long flags pass
{
    my $cap = run_command('Amin::Command::Wget', 'wget', 'dryrun',
        [flag  => 'quiet'],
        [flag  => 'no-check-certificate'],
        [flag  => 'timeout', '30'],
        [param => 'url', 'https://example.com/x.tar.xz']);
    my $argv = stream_text($cap, 'argv');
    like($argv, qr{^wget\b},                     'Wget argv starts with wget');
    like($argv, qr{--quiet},                     'Wget: --quiet passes');
    like($argv, qr{--no-check-certificate},      'Wget: --no-check-certificate passes');
    like($argv, qr{--timeout=30},                'Wget: --timeout=30 passes');
    like($argv, qr{https://example\.com/x\.tar\.xz}, 'Wget: url param passed');
}

# Chmod: mode_tgt structure — mode before targets
{
    my $cap = run_command('Amin::Command::Chmod', 'chmod', 'dryrun',
        [flag  => 'R'],
        [param => 'mode', '0755'],
        [param => 'target', '/tmp/x']);
    like(stream_text($cap, 'argv'), qr{^chmod\s+-R\s+0755\s+/tmp/x},
        'Chmod: mode_tgt — mode before target');
}

# Sed: script structure — script before files
{
    my $cap = run_command('Amin::Command::Sed', 'sed', 'dryrun',
        [flag  => 'n'],
        [param => 'script', 's/foo/bar/g'],
        [param => 'target', 'input.txt']);
    like(stream_text($cap, 'argv'), qr{^sed\s+-n\s+s/foo/bar/g\s+input\.txt},
        'Sed: script — script before target files');
}

# Mount: dev_tgt structure — device before mountpoint
{
    my $cap = run_command('Amin::Command::Mount', 'mount', 'dryrun',
        [flag  => 't', 'ext4'],
        [param => 'device', '/dev/sda1'],
        [param => 'target', '/mnt']);
    like(stream_text($cap, 'argv'), qr{^mount\s+-text4\s+/dev/sda1\s+/mnt},
        'Mount: dev_tgt — device before mountpoint');
}

# Dd: key=value params
{
    my $cap = run_command('Amin::Command::Dd', 'dd', 'dryrun',
        [param => 'if', '/dev/zero'],
        [param => 'of', '/tmp/ddtest'],
        [param => 'bs', '1M'],
        [param => 'count', '1']);
    my $argv = stream_text($cap, 'argv');
    like($argv, qr{^dd\b},                       'Dd argv starts with dd');
    like($argv, qr{if=/dev/zero},                'Dd: if= keyval');
    like($argv, qr{of=/tmp/ddtest},              'Dd: of= keyval');
    like($argv, qr{bs=1M},                       'Dd: bs= keyval');
    like($argv, qr{count=1},                     'Dd: count= keyval');
}

# True: no_pos structure — flags only
{
    my $cap = run_command('Amin::Command::True', 'true', 'dryrun');
    like(stream_text($cap, 'argv'), qr{^true$},
        'True: no_pos — command name only, no positionals');
}

# Bash: all structure — all param values passed positionally
{
    my $cap = run_command('Amin::Command::Bash', 'bash', 'dryrun',
        [param => 'text', 'echo'],
        [param => 'text', 'hi']);
    like(stream_text($cap, 'argv'), qr{^bash\s+echo\s+hi},
        'Bash: all — all param values passed positionally');
}

# ── end-to-end: dryrun emits result/status without executing ──
{
    my $cap = run_command('Amin::Command::Cp', 'cp', 'dryrun',
        [flag  => 'r'],
        [param => 'src', '/etc/hosts'],
        [param => 'dst', '/tmp/hosts.bak']);
    is(result_kind($cap), 'dryrun', 'Cp dryrun: <result kind=dryrun>');
    ok(length(stream_text($cap, 'argv')) > 0, 'Cp dryrun: argv stream emitted');
    is(stream_text($cap, 'out'), '', 'Cp dryrun: no stdout stream (process not spawned)');
    is(status_attrs($cap)->{kind}, 'dryrun', 'Cp dryrun: status kind = dryrun');
    is(status_attrs($cap)->{rc},   '0',      'Cp dryrun: status rc = 0');
}

# ── end-to-end: run mode executes a real command ──
{
    my $cap = run_command('Amin::Command::Pwd', 'pwd', 'run');
    is(result_kind($cap), 'running', 'Pwd run-mode: <result kind=running> before exec');
    ok(length(stream_text($cap, 'out')) > 0, 'Pwd run-mode: stdout stream emitted');
    is(status_attrs($cap)->{kind}, 'success', 'Pwd run-mode: status kind = success');
    is(status_attrs($cap)->{rc},   '0',       'Pwd run-mode: status rc = 0');
    ok(defined status_attrs($cap)->{pid},     'Pwd run-mode: status pid populated');
    like(status_attrs($cap)->{duration}, qr{^[0-9]+\.[0-9]+$}, 'Pwd run-mode: duration is float seconds');
}

done_testing;
