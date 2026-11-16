package Amin::AI::Provider::Registry;
use v5.38; use warnings; use utf8; use experimental 'signatures';

# ═══════════════════════════════════════════════════════════════════════════
# Amin::AI::Provider::Registry — api id → adapter class.
#
# A profile NAMES a provider (api= / provider= on <ai:provider>); it can
# never DEFINE one.  Plugins (shipped as signed bundle filters) call
# register() to add an id.  Selection order: explicit api=, then provider=,
# then a base-url hint, then the generic compat adapter.
# ═══════════════════════════════════════════════════════════════════════════

my %DEFAULT = (
    openai        => 'Amin::AI::Provider::OpenAICompat',
    openai_compat => 'Amin::AI::Provider::OpenAICompat',
    openrouter    => 'Amin::AI::Provider::OpenRouter',
    deepinfra     => 'Amin::AI::Provider::DeepInfra',
    stub          => 'Amin::AI::Provider::Stub',
);

my %BY_API = %DEFAULT;

sub register ($pkg, $api, $class) {
    return unless defined $api && length $api && defined $class && length $class;
    $BY_API{ lc $api } = $class;
    return $class;
}

sub reset ($pkg = __PACKAGE__) { %BY_API = %DEFAULT; return }

sub class_for ($pkg, $bind) {
    $bind //= {};
    my $api = lc($bind->{api} // '');
    return $BY_API{$api} if length $api && $BY_API{$api};
    my $p = lc($bind->{provider} // '');
    return $BY_API{$p} if length $p && $BY_API{$p};
    my $b = lc($bind->{base} // '');
    return 'Amin::AI::Provider::DeepInfra' if $b =~ /deepinfra/;
    return 'Amin::AI::Provider::OpenRouter' if $b =~ /openrouter/;
    return 'Amin::AI::Provider::OpenAICompat';
}

sub for_binding ($pkg, $bind) {
    $bind //= {};
    my $class = $pkg->class_for($bind);
    (my $file = $class) =~ s{::}{/}g;
    require "$file.pm";
    return $class->new(%$bind);
}

1;
