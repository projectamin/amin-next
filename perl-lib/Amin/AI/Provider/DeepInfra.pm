package Amin::AI::Provider::DeepInfra;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI::Provider::AsyncHttp';

# ═══════════════════════════════════════════════════════════════════════════
# DeepInfra serves open-weight models (ACE-Step music) behind a submit →
# poll inference API.  The paths and vocabulary are the AsyncHttp defaults;
# this adapter exists so `api=deepinfra` selects it and defaults the model.
# ═══════════════════════════════════════════════════════════════════════════

sub submit_path ($self) { 'v1/inference/%s' }
sub poll_path   ($self) { 'v1/inference/%s/%s' }

1;
