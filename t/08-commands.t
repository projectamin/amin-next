#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Command::Mkdir;
use Amin::Command::Echo;
use Amin::Command::Remove;
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

sub argv_text ($cap) {
    my $in = 0; my $text = '';
    for my $ev ($cap->captured->@*) {
        my ($m, @a) = @$ev;
        if ($m eq 'start_element') {
            my $e = $a[0];
            if (($e->{LocalName} // '') eq 'stream') {
                my $ch = $e->{Attributes}{'{}channel'};
                $in = ($ch && $ch->{Value} eq 'argv') ? 1 : 0;
            }
        } elsif ($m eq 'characters' && $in) {
            $text .= $a[0]{Data} // '';
        } elsif ($m eq 'end_element') {
            $in = 0 if ($a[0]{LocalName} // '') eq 'stream';
        }
    }
    return $text;
}

# ── Mkdir: targets structure, -p short + --mode long-valued ──
{
    my $cap = run_command('Amin::Command::Mkdir', 'mkdir', 'dryrun',
        [flag  => 'p'],
        [flag  => 'mode', '0755'],
        [param => 'target', '/a'],
        [param => 'target', '/b/c']);
    my $argv = argv_text($cap);
    like($argv, qr{^mkdir\b},                    'Mkdir: command name mkdir');
    like($argv, qr{\s-p\b},                      'Mkdir: short -p flag');
    like($argv, qr{--mode=0755},                 'Mkdir: long --mode=0755 flag');
    like($argv, qr{/a\b},                        'Mkdir: target /a');
    like($argv, qr{/b/c\b},                      'Mkdir: target /b/c');
}

# Mkdir: no targets → empty argv (no result emitted)
{
    my $cap = run_command('Amin::Command::Mkdir', 'mkdir', 'dryrun');
    is(argv_text($cap), '', 'Mkdir: no targets → empty argv (no result)');
}

# ── Echo: named:text + raw params + e/n flags ──
{
    my $cap = run_command('Amin::Command::Echo', 'echo', 'dryrun',
        [flag  => 'e'],
        [flag  => 'n'],
        [param => 'text', 'hi'],
        [param => 'text', 'world']);
    like(argv_text($cap), qr{^echo\s+-en\s+hi\s+world},
        'Echo: combines named:text params + e/n flags into one invocation');
}

# ── Remove: short flags r+f concatenated as -rf ──
{
    my $cap = run_command('Amin::Command::Remove', 'remove', 'dryrun',
        [flag  => 'r'],
        [flag  => 'f'],
        [param => 'target', '/tmp/x'],
        [param => 'target', '/var/tmp/y']);
    like(argv_text($cap), qr{^rm\s+-rf\s+/tmp/x\s+/var/tmp/y},
        'Remove: short flags r+f become -rf concatenated');
}

# Remove: allowed long names kept; not_in_allowed dropped (closed-world)
{
    my $cap = run_command('Amin::Command::Remove', 'remove', 'dryrun',
        [flag  => 'recursive'],
        [flag  => 'force'],
        [flag  => 'verbose'],
        [flag  => 'not_in_allowed', '1'],
        [param => 'target', '/tmp/x'],
        [param => 'target', '/var/tmp/y']);
    my $argv = argv_text($cap);
    like($argv, qr{^rm\b},                    'Remove: command name rm');
    like($argv, qr{--recursive},              'Remove: --recursive kept');
    like($argv, qr{--force},                  'Remove: --force kept');
    unlike($argv, qr{--verbose},              'Remove: verbose NOT in allowlist → DROPPED');
    unlike($argv, qr{not_in_allowed},         'Remove: not_in_allowed DROPPED (closed-world)');
}

# Remove: short v flag IS allowed
{
    my $cap = run_command('Amin::Command::Remove', 'remove', 'dryrun',
        [flag  => 'v'],
        [flag  => 'recursive'],
        [param => 'target', '/tmp/x'],
        [param => 'target', '/var/tmp/y']);
    my $argv = argv_text($cap);
    like($argv, qr{-v},                       'Remove: short v flag IS allowed');
    like($argv, qr{--recursive},              'Remove: --recursive also present');
}

is(Amin::Command::Mkdir->name,    'mkdir',  'Mkdir filter name');
is(Amin::Command::Echo->name,     'echo',   'Echo filter name');
is(Amin::Command::Remove->name,   'remove', 'Remove filter name');
is(Amin::Command::Mkdir->element, 'command','all 3 declare element=command');

done_testing;
