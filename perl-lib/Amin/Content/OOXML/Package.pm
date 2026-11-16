package Amin::Content::OOXML::Package;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';

# ═══════════════════════════════════════════════════════════════════════════
# Amin::Content::OOXML::Package — deterministic multi-part ZIP packages.
#
# OOXML (xlsx/docx/pptx) is a ZIP of XML parts.  We build it directly rather
# than through a CPAN archive module so every byte is reproducible:
#   • parts are emitted in sorted-name order,
#   • every entry carries the fixed DOS timestamp 1980-01-01 00:00,
#   • the same content therefore always produces the same BLAKE3 artifact hash.
#
# The reader is deliberately bounded: OOXML packages are untrusted input, so
# entry count, per-part size, total size and compression ratio are capped
# before anything is inflated.
# ═══════════════════════════════════════════════════════════════════════════

use Compress::Raw::Zlib qw(crc32 Z_OK Z_STREAM_END Z_FINISH MAX_WBITS);

my $DOS_TIME = 0x0000;                   # 00:00:00
my $DOS_DATE = 0x0021;                   # 1980-01-01
my $UTF8_FLAG = 0x0800;

sub new ($class, %o) {
    return bless { parts => {}, %o }, $class;
}

sub add_part ($self, $name, $bytes) {
    die "package part name is empty\n"
        unless defined $name && length $name;
    die "package part '$name' contains a NUL byte\n" if $name =~ /\0/;
    $self->{parts}{$name} = defined $bytes ? "$bytes" : '';
    return $self;
}

sub part_names ($self) {
    return sort keys %{ $self->{parts} };
}

sub finish ($self) {
    my @names = $self->part_names;
    my ($body, $central) = ('', '');
    my $offset = 0;

    for my $name (@names) {
        my $raw = $self->{parts}{$name};
        my ($method, $data) = _compress($raw);
        my $crc = crc32($raw);
        my $name_len = length $name;
        my $local = pack('V v v v v v V V V v v',
            0x04034b50, 20, $UTF8_FLAG, $method, $DOS_TIME, $DOS_DATE,
            $crc, length($data), length($raw), $name_len, 0
        ) . $name;
        $body .= $local . $data;

        $central .= pack('V v v v v v v V V V v v v v v V V',
            0x02014b50, 20, 20, $UTF8_FLAG, $method, $DOS_TIME, $DOS_DATE,
            $crc, length($data), length($raw),
            $name_len, 0, 0, 0, 0, 0, $offset
        ) . $name;

        $offset += length($local) + length($data);
    }

    my $cd_offset = length $body;
    my $eocd = pack('V v v v v V V v',
        0x06054b50, 0, 0, scalar(@names), scalar(@names),
        length($central), $cd_offset, 0
    );
    return $body . $central . $eocd;
}

sub _compress ($raw) {
    my $deflate = Compress::Raw::Zlib::Deflate->new(
        -WindowBits => -MAX_WBITS, -Level => 9, -AppendOutput => 1
    ) or return (0, $raw);
    my $out = '';
    my $status = $deflate->deflate($raw, $out);
    return (0, $raw) if $status != Z_OK;
    $status = $deflate->flush($out, Z_FINISH);
    return (0, $raw) if $status != Z_OK && $status != Z_STREAM_END;
    # Storing a tiny part is smaller and just as valid.
    return (0, $raw) if length($out) >= length($raw);
    return (8, $out);
}

# ── bounded reader (tests and the import path) ──────────────────────────
# Returns a hashref name → bytes.  Dies on a malformed/over-limit package so
# callers can turn the failure into a amin:result error code.
sub read_parts ($class, $bytes, %o) {
    my $max_entries = $o{max_entries} // 10_000;
    my $max_part    = $o{max_part}    // (64 * 1024 * 1024);
    my $max_total   = $o{max_total}   // (256 * 1024 * 1024);

    die "empty zip\n" unless defined $bytes && length $bytes;
    my $eocd_at = rindex($bytes, "PK\x05\x06");
    die "zip end-of-central-directory not found\n" if $eocd_at < 0;
    die "truncated zip end-of-central-directory\n" if $eocd_at + 22 > length $bytes;

    my (undef, undef, undef, $count, undef, $cd_size, $cd_offset)
        = unpack('V v v v v V V v', substr($bytes, $eocd_at, 22));
    die "zip64 packages are not supported\n"
        if $count == 0xFFFF || $cd_offset == 0xFFFFFFFF || $cd_size == 0xFFFFFFFF;
    die "zip entry count $count exceeds limit $max_entries\n" if $count > $max_entries;
    die "zip central directory is out of bounds\n"
        if $cd_offset + $cd_size > length($bytes);

    my %parts;
    my $total = 0;
    my $p = $cd_offset;
    for my $i (0 .. $count - 1) {
        die "truncated zip central directory\n" if $p + 46 > length $bytes;
        my $sig = unpack('V', substr($bytes, $p, 4));
        die "bad zip central-directory signature\n" if $sig != 0x02014b50;

        my (undef, undef, undef, $flags, $method, undef, undef,
            $crc, $comp_size, $uncomp_size, $name_len, $extra_len,
            $comment_len, undef, undef, undef, $local_at)
            = unpack('V v v v v v v V V V v v v v v V V',
                     substr($bytes, $p, 46));
        my $name = substr($bytes, $p + 46, $name_len);
        $p += 46 + $name_len + $extra_len + $comment_len;

        die "zip entry '$name' declares $uncomp_size bytes (limit $max_part)\n"
            if $uncomp_size > $max_part;
        die "zip entry '$name' is encrypted\n" if $flags & 0x0001;
        die "zip entry '$name' uses unsupported method $method\n"
            if $method != 0 && $method != 8;

        die "zip local header out of bounds for '$name'\n"
            if $local_at + 30 > length $bytes;
        die "bad zip local-header signature for '$name'\n"
            if unpack('V', substr($bytes, $local_at, 4)) != 0x04034b50;
        my (undef, undef, undef, $l_method, undef, undef, undef,
            undef, undef, $l_name_len, $l_extra_len)
            = unpack('V v v v v v V V V v v', substr($bytes, $local_at, 30));
        my $data_at = $local_at + 30 + $l_name_len + $l_extra_len;
        die "zip entry '$name' data is out of bounds\n"
            if $data_at + $comp_size > length $bytes;
        my $data = substr($bytes, $data_at, $comp_size);

        if ($l_method == 8) {
            $data = _inflate_raw($data, $uncomp_size, $name, $max_part);
        }
        die "zip entry '$name' is larger than declared\n"
            if length($data) > $max_part;
        $total += length $data;
        die "zip expands to more than $max_total bytes\n" if $total > $max_total;
        $parts{$name} = $data;
    }
    return \%parts;
}

sub _inflate_raw ($data, $expect, $name, $limit) {
    my $inflate = Compress::Raw::Zlib::Inflate->new(
        -WindowBits => -MAX_WBITS, -AppendOutput => 1
    ) or die "cannot initialise zip inflater\n";
    my $out = '';
    my $off = 0;
    while ($off < length $data) {
        # Feed bounded chunks so a header that under-declares its uncompressed
        # size cannot make us allocate an unbounded buffer before the check.
        my $chunk = substr($data, $off, 16 * 1024);
        $off += length $chunk;
        my $status = $inflate->inflate($chunk, $out);
        die "cannot inflate zip entry '$name'\n"
            if $status != Z_OK && $status != Z_STREAM_END;
        die "zip entry '$name' exceeds the part size limit\n"
            if length($out) > $limit;
        last if $status == Z_STREAM_END;
    }
    die "zip entry '$name' inflated to the wrong size\n"
        if $expect && length($out) != $expect;
    return $out;
}

1;
