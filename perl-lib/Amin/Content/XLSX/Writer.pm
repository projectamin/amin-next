package Amin::Content::XLSX::Writer;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';

use Amin::Content::OOXML::Package;

# ═══════════════════════════════════════════════════════════════════════════
# Amin::Content::XLSX::Writer — dependency-free OOXML spreadsheet writer.
#
# The writer is driven by Amin::Content::Document:
#   start_document(\%attrs)
#   handle_start($local_name, \%attrs)
#   handle_text($local_name, $text, \%attrs)
#   handle_end($local_name)
#   finish() → ($zip_bytes, $error)
#
# Everything is deterministic: no wall-clock timestamps, no random ids, parts
# in sorted order.  That is what makes the emitted bc:object hash stable.
# ═══════════════════════════════════════════════════════════════════════════

use constant {
    MAX_ROWS       => 1_048_576,
    MAX_COLS       => 16_384,
    MAX_CELLS      => 1_000_000,
    MAX_TEXT       => 32_767,
    MAX_SHEET_NAME => 31,
    MAX_BYTES      => 256 * 1024 * 1024,
    FIXED_TS       => '1980-01-01T00:00:00Z',
};

my $NS_MAIN      = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
my $NS_R         = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
my $NS_PKG_REL   = 'http://schemas.openxmlformats.org/package/2006/relationships';
my $NS_CT        = 'http://schemas.openxmlformats.org/package/2006/content-types';
my $NS_CP        = 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties';
my $NS_DC        = 'http://purl.org/dc/elements/1.1/';
my $NS_DCTERMS   = 'http://purl.org/dc/terms/';
my $NS_XSI       = 'http://www.w3.org/2001/XMLSchema-instance';
my $NS_EP        = 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties';
my $NS_VT        = 'http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes';

sub new ($class, %o) {
    my $self = bless {
        title       => $o{title}       // 'Amin Content',
        author      => $o{author}      // 'Amin',
        subject     => $o{subject},
        keywords    => $o{keywords},
        description => $o{description},
        sheets      => [],
        sheet_names => {},
        current     => undef,
        pending     => undef,
        error       => undef,
        stats       => { rows => 0, cells => 0 },
        styles      => {
            style_index => {},
            fonts       => [],
            font_by_key => {},
            fills       => [],
            fill_by_key => {},
            xfs         => [],
            xf_by_key   => {},
            numfmts     => { 164 => 'yyyy-mm-dd', 165 => 'yyyy-mm-dd hh:mm:ss' },
            next_numfmt => 166,
        },
    }, $class;
    $self->_init_styles;
    return $self;
}

sub format { 'xlsx' }
sub mime   { 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }
sub error  { $_[0]{error} }
sub stats  { $_[0]{stats} }
sub sheet_count { scalar @{ $_[0]{sheets} } }

sub is_text_element ($self, $ln) { return $ln eq 'cell' }

sub start_document ($self, $attrs = {}) {
    for my $k (qw(title author subject keywords description)) {
        next unless defined $attrs->{$k} && length $attrs->{$k};
        $self->{$k} = $attrs->{$k};
    }
    return;
}

sub handle_start ($self, $ln, $attrs = {}) {
    return if $self->{error};
    if ($ln eq 'style') {
        my $id = $attrs->{id};
        return $self->_fail('amin:style requires an id') unless defined $id && length $id;
        $self->_register_style($id, $attrs);
        return;
    }
    return $self->_start_sheet($attrs)  if $ln eq 'sheet';
    return $self->_start_row($attrs)    if $ln eq 'row';
    return $self->_add_column($attrs)   if $ln eq 'column';
    return $self->_add_merge($attrs)    if $ln eq 'merge';
    return $self->_set_freeze($attrs)   if $ln eq 'freeze';
    return $self->_set_filter($attrs)   if $ln eq 'autofilter';
    if ($ln eq 'cell') {
        $self->{pending} = { %$attrs };
        return;
    }
    return;
}

sub handle_text ($self, $ln, $text, $attrs = {}) {
    return if $self->{error};
    return unless $ln eq 'cell';
    my $a = $self->{pending} // $attrs;
    $a->{_wrote_text} = 1;
    $self->_write_cell($a, $text);
    return;
}

sub handle_end ($self, $ln) {
    if ($ln eq 'cell') {
        my $a = $self->{pending};
        if ($a && !$a->{_wrote_text} && lc($a->{type} // '') eq 'blank') {
            $self->_write_cell($a, '');
        }
        $self->{pending} = undef;
        return;
    }
    if ($ln eq 'row')   { $self->{current}{current_row} = undef if $self->{current}; return }
    if ($ln eq 'sheet') { $self->{current} = undef; return }
    return;
}

sub finish ($self) {
    return (undef, $self->{error}) if $self->{error};
    return (undef, 'amin:document format=xlsx requires at least one amin:sheet')
        unless @{ $self->{sheets} };

    $self->{stats}{rows} = 0;
    for my $sheet (@{ $self->{sheets} }) {
        $self->{stats}{rows} += grep { keys %{ $_->{cell_by_c} } } @{ $sheet->{rows} };
    }

    my ($bytes, $err) = eval { ($self->_build, undef) };
    return (undef, "xlsx build failed: $@") if $@;
    return (undef, 'xlsx output exceeds the 256 MiB cap') if length($bytes) > MAX_BYTES;
    return ($bytes, undef);
}

# ── styles ──────────────────────────────────────────────────────────────

sub _init_styles ($self) {
    $self->_font_id({ size => 11, name => 'Calibri' });
    my $s = $self->{styles};
    for my $fill ([ none => undef ], [ gray125 => 'gray125' ]) {
        my ($key, $type) = @$fill;
        $s->{fills}[ scalar @{ $s->{fills} } ] = $type
            ? { pattern => 'gray125' }
            : { pattern => 'none' };
        $s->{fill_by_key}{$key} = $#{ $s->{fills} };
    }
    $self->_xf_id({ fontId => 0, fillId => 0, numFmtId => 0, borderId => 0 });
    $s->{style_index}{default} = 0;
    $self->_register_style('__date',     { numfmt => 'date' });
    $self->_register_style('__datetime', { numfmt => 'datetime' });
    return;
}

sub _register_style ($self, $id, $a) {
    my $s = $self->{styles};
    return if exists $s->{style_index}{$id};

    my $font_id = $self->_font_id({
        size      => _int_between($a->{size}, 1, 409) // 11,
        name      => _font_name($a->{font}),
        bold      => _truth($a->{bold}),
        italic    => _truth($a->{italic}),
        underline => _truth($a->{underline}),
        color     => _argb($a->{color}),
    });
    my $fill_id = 0;
    if (defined(my $argb = _argb($a->{fill}))) {
        $fill_id = $self->_fill_id($argb);
    }
    my $numfmt_id = $self->_numfmt_id($a->{numfmt} // $a->{format});

    my %alignment;
    $alignment{horizontal} = $a->{align}   if defined $a->{align};
    $alignment{vertical}   = $a->{valign}  if defined $a->{valign};
    $alignment{wrapText}   = 1 if _truth($a->{wrap});

    $s->{style_index}{$id} = $self->_xf_id({
        fontId    => $font_id,
        fillId    => $fill_id,
        numFmtId  => $numfmt_id,
        borderId  => 0,
        alignment => \%alignment,
    });
    return;
}

sub _font_id ($self, $font) {
    my $s = $self->{styles};
    my $key = join '|', $font->{bold} ? 1 : 0, $font->{italic} ? 1 : 0,
        $font->{underline} ? 1 : 0, $font->{size}, $font->{name},
        $font->{color} // '';
    return $s->{font_by_key}{$key} if exists $s->{font_by_key}{$key};
    push @{ $s->{fonts} }, $font;
    return $s->{font_by_key}{$key} = $#{ $s->{fonts} };
}

sub _fill_id ($self, $argb) {
    my $s = $self->{styles};
    return $s->{fill_by_key}{$argb} if exists $s->{fill_by_key}{$argb};
    push @{ $s->{fills} }, { pattern => 'solid', fgColor => $argb };
    return $s->{fill_by_key}{$argb} = $#{ $s->{fills} };
}

sub _xf_id ($self, $xf) {
    my $s = $self->{styles};
    my $align = $xf->{alignment} // {};
    my $key = join '|', $xf->{fontId}, $xf->{fillId}, $xf->{numFmtId},
        $xf->{borderId}, map { "$_=" . ($align->{$_} // '') } sort keys %$align;
    return $s->{xf_by_key}{$key} if exists $s->{xf_by_key}{$key};
    push @{ $s->{xfs} }, { %$xf };
    return $s->{xf_by_key}{$key} = $#{ $s->{xfs} };
}

sub _numfmt_id ($self, $fmt) {
    return 0 unless defined $fmt && length $fmt;
    my $s = $self->{styles};
    my %named = (
        general => 0, integer => 1, decimal => 2, money => 4,
        percent => 10, date => 164, datetime => 165,
    );
    my $lc = lc $fmt;
    return $named{$lc} if exists $named{$lc};
    return $fmt + 0 if $fmt =~ /^\d+$/;
    for my $id (sort { $a <=> $b } keys %{ $s->{numfmts} }) {
        return $id if $s->{numfmts}{$id} eq $fmt;
    }
    my $id = $s->{next_numfmt}++;
    $s->{numfmts}{$id} = $fmt;
    return $id;
}

# ── sheets / rows / cells ───────────────────────────────────────────────

sub _start_sheet ($self, $a) {
    return $self->_fail('nested amin:sheet is not supported') if $self->{current};
    my $n = scalar @{ $self->{sheets} };
    my $name = defined $a->{name} && length $a->{name} ? $a->{name} : 'Sheet' . ($n + 1);
    $name =~ s/^\s+|\s+$//g;
    return $self->_fail('sheet name is empty') unless length $name;
    return $self->_fail("sheet name '$name' is longer than 31 characters")
        if length($name) > MAX_SHEET_NAME;
    return $self->_fail("sheet name '$name' contains an illegal character")
        if $name =~ m{[\[\]:*?/\\]};
    return $self->_fail("duplicate sheet name '$name'")
        if $self->{sheet_names}{ lc $name }++;

    my $sheet = {
        name       => $name,
        rows       => [],
        row_by_r   => {},
        cols       => [],
        merges     => [],
        freeze     => undef,
        filter     => undef,
        tab_color  => _argb($a->{'tab-color'}),
        next_row   => 1,
        next_col   => 1,
        max_row    => 0,
        max_col    => 0,
        current_row=> undef,
    };
    push @{ $self->{sheets} }, $sheet;
    $self->{current} = $sheet;
    return;
}

sub _start_row ($self, $a) {
    my $sheet = $self->{current}
        or return $self->_fail('amin:row outside amin:sheet');
    my $r = $a->{r};
    if (defined $r && length $r) {
        $r = _int_between($r, 1, MAX_ROWS);
        return $self->_fail("row '$a->{r}' is out of range") unless defined $r;
    } else {
        $r = $sheet->{next_row};
    }

    my $row = $sheet->{row_by_r}{$r};
    if (!$row) {
        $row = { r => $r, height => undef, cells => [], cell_by_c => {} };
        push @{ $sheet->{rows} }, $row;
        $sheet->{row_by_r}{$r} = $row;
    }
    my $height = $a->{height} // $a->{ht};
    if (defined $height && length $height) {
        my $h = _int_between($height, 0, 409);
        return $self->_fail("row height '$height' is out of range") unless defined $h;
        $row->{height} = $h;
    }
    $sheet->{current_row} = $row;
    $sheet->{next_row}    = $r + 1;
    $sheet->{next_col}    = 1;
    return;
}

sub _write_cell ($self, $a, $text) {
    my $sheet = $self->{current}
        or return $self->_fail('amin:cell outside amin:sheet');
    my $row = $sheet->{current_row}
        or return $self->_fail('amin:cell outside amin:row');

    my ($col, $r, $ref);
    if (defined $a->{ref} && length $a->{ref}) {
        ($col, $r) = _split_ref($a->{ref});
        return $self->_fail("invalid cell ref '$a->{ref}'") unless $col;
        $row = $self->_ensure_row($sheet, $r);
        $sheet->{current_row} = $row;
        $ref = uc $a->{ref};
    } else {
        $col = $sheet->{next_col};
        $r   = $row->{r};
        $ref = _num_to_col($col) . $r;
    }
    return $self->_fail("cell $ref column is out of range") if $col < 1 || $col > MAX_COLS;

    $sheet->{next_col} = $col + 1;
    $sheet->{max_col}  = $col if $col > $sheet->{max_col};
    $sheet->{max_row}  = $r   if $r   > $sheet->{max_row};

    my $type = lc($a->{type} // 'string');
    $type =~ s/\s+//g;
    my $value = _trim($text);
    my $cell = { c => $col, ref => $ref };

    if (defined(my $style = $a->{style})) {
        $cell->{style} = $self->{styles}{style_index}{$style} // 0;
    }

    if ($type eq 'blank') {
        $cell->{blank} = 1;
    }
    elsif ($type eq 'string' || $type eq 'text') {
        return $self->_fail("cell $ref text exceeds 32767 characters")
            if length($value) > MAX_TEXT;
        $cell->{t} = 'inlineStr';
        $cell->{v} = $value;
    }
    elsif ($type eq 'number' || $type eq 'decimal' || $type eq 'integer') {
        return $self->_fail("cell $ref has an invalid number '$value'")
            unless _is_number($value);
        $cell->{v} = $value;
    }
    elsif ($type eq 'date' || $type eq 'datetime') {
        my $serial = _excel_serial($value);
        return $self->_fail("cell $ref has an invalid date '$value'")
            unless defined $serial;
        $cell->{v} = $serial;
        $cell->{style} //= $self->{styles}{style_index}{
            $type eq 'date' ? '__date' : '__datetime' };
    }
    elsif ($type eq 'formula') {
        (my $f = $value) =~ s/^=//;
        return $self->_fail("cell $ref has an empty formula") unless length $f;
        $cell->{formula} = $f;
        $cell->{v} = '0';
    }
    elsif ($type eq 'bool' || $type eq 'boolean') {
        $cell->{t} = 'b';
        $cell->{v} = _truth($value) ? 1 : 0;
    }
    else {
        return $self->_fail("cell $ref has unsupported type '$type'");
    }

    if (my $old = $row->{cell_by_c}{$col}) {
        $self->{stats}{cells}--;
    }
    $row->{cell_by_c}{$col} = $cell;
    $self->{stats}{cells}++;
    return $self->_fail("spreadsheet exceeds the " . MAX_CELLS . "-cell cap")
        if $self->{stats}{cells} > MAX_CELLS;
    return;
}

sub _ensure_row ($self, $sheet, $r) {
    return $self->_fail("row $r is out of range") if $r < 1 || $r > MAX_ROWS;
    return $sheet->{row_by_r}{$r} if $sheet->{row_by_r}{$r};
    my $row = { r => $r, height => undef, cells => [], cell_by_c => {} };
    push @{ $sheet->{rows} }, $row;
    $sheet->{row_by_r}{$r} = $row;
    return $row;
}

sub _add_column ($self, $a) {
    my $sheet = $self->{current}
        or return $self->_fail('amin:column outside amin:sheet');
    my $next = @{ $sheet->{cols} } ? ($sheet->{cols}[-1]{max} // 0) + 1 : 1;
    my $min_raw = $a->{index} // $a->{min};
    my $min = defined $min_raw && length $min_raw
        ? _int_between($min_raw, 1, MAX_COLS)
        : $next;
    return $self->_fail("column '$min_raw' is out of range") unless defined $min;
    my $max_raw = $a->{max};
    my $max = defined $max_raw && length $max_raw
        ? _int_between($max_raw, 1, MAX_COLS)
        : $min;
    return $self->_fail("column range is invalid") unless defined $max && $max >= $min;
    my $width = $a->{width};
    if (defined $width) {
        return $self->_fail("column width '$width' is invalid")
            unless $width =~ /^\d+(?:\.\d+)?$/ && $width >= 0 && $width <= 255;
    }
    push @{ $sheet->{cols} }, {
        min    => $min,
        max    => $max,
        width  => $width,
        hidden => _truth($a->{hidden}),
    };
    return;
}

sub _add_merge ($self, $a) {
    my $sheet = $self->{current}
        or return $self->_fail('amin:merge outside amin:sheet');
    my $ref = uc($a->{ref} // $a->{range} // '');
    return $self->_fail("invalid merge ref '$ref'")
        unless $ref =~ /^([A-Z]{1,3}\d+):([A-Z]{1,3}\d+)$/;
    my ($c1, $r1) = _split_ref($1);
    my ($c2, $r2) = _split_ref($2);
    return $self->_fail("merge ref '$ref' is out of range") unless $c1 && $c2;
    return $self->_fail("merge ref '$ref' is reversed")
        if $c2 < $c1 || $r2 < $r1;
    push @{ $sheet->{merges} }, $ref;
    $sheet->{max_col} = $c2 if $c2 > $sheet->{max_col};
    $sheet->{max_row} = $r2 if $r2 > $sheet->{max_row};
    return;
}

sub _set_freeze ($self, $a) {
    my $sheet = $self->{current}
        or return $self->_fail('amin:freeze outside amin:sheet');
    my $ref = uc($a->{ref} // $a->{cell} // '');
    my ($col, $row) = _split_ref($ref);
    return $self->_fail("invalid freeze ref '$ref'") unless $col;
    $sheet->{freeze} = $ref;
    return;
}

sub _set_filter ($self, $a) {
    my $sheet = $self->{current}
        or return $self->_fail('amin:autofilter outside amin:sheet');
    my $ref = uc($a->{ref} // $a->{range} // '');
    return $self->_fail("invalid autofilter ref '$ref'")
        unless $ref =~ /^[A-Z]{1,3}\d+(?::[A-Z]{1,3}\d+)?$/;
    $sheet->{filter} = $ref;
    return;
}

sub _fail ($self, $msg) {
    $self->{error} //= $msg;
    return;
}

# ── package build ───────────────────────────────────────────────────────

sub _build ($self) {
    my $pkg = Amin::Content::OOXML::Package->new;
    my @sheets = @{ $self->{sheets} };
    for my $i (0 .. $#sheets) {
        $pkg->add_part("xl/worksheets/sheet" . ($i + 1) . '.xml',
            $self->_sheet_xml($sheets[$i]));
    }
    $pkg->add_part('xl/styles.xml',  $self->_styles_xml);
    $pkg->add_part('xl/workbook.xml', $self->_workbook_xml);
    $pkg->add_part('xl/_rels/workbook.xml.rels', $self->_workbook_rels_xml);
    $pkg->add_part('_rels/.rels', $self->_root_rels_xml);
    $pkg->add_part('[Content_Types].xml', $self->_content_types_xml);
    $pkg->add_part('docProps/core.xml', $self->_core_xml);
    $pkg->add_part('docProps/app.xml',  $self->_app_xml);
    return $pkg->finish;
}

sub _sheet_xml ($self, $sheet) {
    my $xml = _decl() . qq{<worksheet xmlns="$NS_MAIN" xmlns:r="$NS_R">};
    $xml .= qq{<sheetPr><tabColor rgb="$sheet->{tab_color}"/></sheetPr>}
        if $sheet->{tab_color};
    if ($sheet->{max_row} && $sheet->{max_col}) {
        my $dim = 'A1:' . _num_to_col($sheet->{max_col}) . $sheet->{max_row};
        $xml .= qq{<dimension ref="$dim"/>};
    }
    $xml .= _sheet_views($sheet);
    $xml .= qq{<sheetFormatPr defaultRowHeight="15"/>};
    $xml .= _cols_xml($sheet);

    $xml .= '<sheetData>';
    for my $row (sort { $a->{r} <=> $b->{r} } @{ $sheet->{rows} }) {
        my @cells = sort { $a->{c} <=> $b->{c} } values %{ $row->{cell_by_c} };
        next unless @cells;
        my $attrs = qq{ r="$row->{r}"};
        if (defined $row->{height}) {
            $attrs .= qq{ ht="$row->{height}" customHeight="1"};
        }
        $xml .= "<row$attrs>" . join('', map { _cell_xml($_) } @cells) . '</row>';
    }
    $xml .= '</sheetData>';
    $xml .= qq{<autoFilter ref="$sheet->{filter}"/>} if $sheet->{filter};
    if (@{ $sheet->{merges} }) {
        $xml .= qq{<mergeCells count="} . scalar(@{ $sheet->{merges} }) . '">';
        $xml .= qq{<mergeCell ref="$_"/>} for @{ $sheet->{merges} };
        $xml .= '</mergeCells>';
    }
    return $xml . '</worksheet>';
}

sub _sheet_views ($sheet) {
    my $freeze = $sheet->{freeze};
    return '<sheetViews><sheetView workbookViewId="0"/></sheetViews>'
        unless $freeze;
    my ($col, $row) = _split_ref($freeze);
    my $xs = $col > 1 ? $col - 1 : 0;
    my $ys = $row > 1 ? $row - 1 : 0;
    return '<sheetViews><sheetView workbookViewId="0"/></sheetViews>'
        unless $xs || $ys;
    my $pane = $xs && $ys ? 'bottomRight'
             : $ys        ? 'bottomLeft'
             :              'topRight';
    my $attrs = '';
    $attrs .= qq{ xSplit="$xs"} if $xs;
    $attrs .= qq{ ySplit="$ys"} if $ys;
    return '<sheetViews><sheetView workbookViewId="0">'
        . qq{<pane$attrs topLeftCell="$freeze" activePane="$pane" state="frozen"/>}
        . qq{<selection pane="$pane" activeCell="$freeze" sqref="$freeze"/>}
        . '</sheetView></sheetViews>';
}

sub _cols_xml ($sheet) {
    my @cols = grep { defined $_->{width} || $_->{hidden} } @{ $sheet->{cols} };
    return '' unless @cols;
    my $xml = '<cols>';
    for my $c (@cols) {
        my $attrs = qq{ min="$c->{min}" max="$c->{max}"};
        if (defined $c->{width}) {
            my $w = sprintf '%.2f', $c->{width};
            $w =~ s/\.?0+$//;
            $attrs .= qq{ width="$w" customWidth="1"};
        }
        $attrs .= ' hidden="1"' if $c->{hidden};
        $xml .= "<col$attrs/>";
    }
    return $xml . '</cols>';
}

sub _cell_xml ($cell) {
    my $s = $cell->{style} ? qq{ s="$cell->{style}"} : '';
    return qq{<c r="$cell->{ref}"$s/>} if $cell->{blank};
    if (defined $cell->{formula}) {
        return qq{<c r="$cell->{ref}"$s><f>}
            . _esc($cell->{formula})
            . qq{</f><v>$cell->{v}</v></c>};
    }
    my $t = $cell->{t} // '';
    if ($t eq 'inlineStr') {
        return qq{<c r="$cell->{ref}"$s t="inlineStr"><is><t xml:space="preserve">}
            . _esc($cell->{v})
            . '</t></is></c>';
    }
    my $ta = $t ? qq{ t="$t"} : '';
    return qq{<c r="$cell->{ref}"$s$ta><v>$cell->{v}</v></c>};
}

sub _styles_xml ($self) {
    my $s = $self->{styles};
    my $xml = _decl() . qq{<styleSheet xmlns="$NS_MAIN">};

    my @numfmts = sort { $a <=> $b } keys %{ $s->{numfmts} };
    if (@numfmts) {
        $xml .= qq{<numFmts count="} . scalar(@numfmts) . '">';
        for my $id (@numfmts) {
            $xml .= qq{<numFmt numFmtId="$id" formatCode="}
                . _esc($s->{numfmts}{$id}) . '"/>';
        }
        $xml .= '</numFmts>';
    }

    $xml .= qq{<fonts count="} . scalar(@{ $s->{fonts} }) . '">';
    for my $f (@{ $s->{fonts} }) {
        $xml .= '<font>';
        $xml .= '<b/>' if $f->{bold};
        $xml .= '<i/>' if $f->{italic};
        $xml .= '<u/>' if $f->{underline};
        $xml .= qq{<sz val="$f->{size}"/>};
        $xml .= qq{<color rgb="$f->{color}"/>} if $f->{color};
        $xml .= qq{<name val="} . _esc($f->{name}) . '"/>';
        $xml .= '<family val="2"/>';
        $xml .= '</font>';
    }
    $xml .= '</fonts>';

    $xml .= qq{<fills count="} . scalar(@{ $s->{fills} }) . '">';
    for my $fill (@{ $s->{fills} }) {
        if ($fill->{pattern} eq 'solid') {
            $xml .= '<fill><patternFill patternType="solid">'
                . qq{<fgColor rgb="$fill->{fgColor}"/><bgColor indexed="64"/>}
                . '</patternFill></fill>';
        } else {
            $xml .= qq{<fill><patternFill patternType="$fill->{pattern}"/></fill>};
        }
    }
    $xml .= '</fills>';

    $xml .= '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>';
    $xml .= '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>';

    $xml .= qq{<cellXfs count="} . scalar(@{ $s->{xfs} }) . '">';
    for my $xf (@{ $s->{xfs} }) {
        my $attrs = qq{ numFmtId="$xf->{numFmtId}" fontId="$xf->{fontId}" }
            . qq{fillId="$xf->{fillId}" borderId="$xf->{borderId}" xfId="0"};
        $attrs .= ' applyNumberFormat="1"' if $xf->{numFmtId};
        $attrs .= ' applyFont="1"' if $xf->{fontId};
        $attrs .= ' applyFill="1"' if $xf->{fillId};
        my $align = $xf->{alignment} // {};
        if (%$align) {
            $xml .= qq{<xf$attrs applyAlignment="1"><alignment}
                . (defined $align->{horizontal} ? qq{ horizontal="$align->{horizontal}"} : '')
                . (defined $align->{vertical}   ? qq{ vertical="$align->{vertical}"}   : '')
                . ($align->{wrapText}           ? ' wrapText="1"'                      : '')
                . '/></xf>';
        } else {
            $xml .= qq{<xf$attrs/>};
        }
    }
    $xml .= '</cellXfs>';
    $xml .= '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>';
    return $xml . '</styleSheet>';
}

sub _workbook_xml ($self) {
    my @sheets = @{ $self->{sheets} };
    my $xml = _decl() . qq{<workbook xmlns="$NS_MAIN" xmlns:r="$NS_R">}
        . '<bookViews><workbookView xWindow="0" yWindow="0" windowWidth="24000" windowHeight="16000"/></bookViews>'
        . '<sheets>';
    for my $i (0 .. $#sheets) {
        my $name = _esc($sheets[$i]{name});
        $xml .= qq{<sheet name="$name" sheetId="} . ($i + 1)
            . qq{" r:id="rId} . ($i + 1) . '"/>';
    }
    return $xml . '</sheets><calcPr calcId="191029"/></workbook>';
}

sub _workbook_rels_xml ($self) {
    my $n = scalar @{ $self->{sheets} };
    my $xml = _decl() . qq{<Relationships xmlns="$NS_PKG_REL">};
    for my $i (1 .. $n) {
        $xml .= qq{<Relationship Id="rId$i" Type="}
            . 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet'
            . qq{" Target="worksheets/sheet$i.xml"/>};
    }
    $xml .= qq{<Relationship Id="rId} . ($n + 1) . qq{" Type="}
        . 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles'
        . qq{" Target="styles.xml"/>};
    return $xml . '</Relationships>';
}

sub _root_rels_xml ($self) {
    my $r = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
    return _decl() . qq{<Relationships xmlns="$NS_PKG_REL">}
        . qq{<Relationship Id="rId1" Type="$r/officeDocument" Target="xl/workbook.xml"/>}
        . qq{<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>}
        . qq{<Relationship Id="rId3" Type="$r/extended-properties" Target="docProps/app.xml"/>}
        . '</Relationships>';
}

sub _content_types_xml ($self) {
    my $main = 'application/vnd.openxmlformats-officedocument.spreadsheetml';
    my $xml = _decl() . qq{<Types xmlns="$NS_CT">}
        . '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        . '<Default Extension="xml" ContentType="application/xml"/>'
        . qq{<Override PartName="/xl/workbook.xml" ContentType="$main.sheet.main+xml"/>}
        . qq{<Override PartName="/xl/styles.xml" ContentType="$main.styles+xml"/>}
        . '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        . '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>';
    my $n = scalar @{ $self->{sheets} };
    for my $i (1 .. $n) {
        $xml .= qq{<Override PartName="/xl/worksheets/sheet$i.xml" ContentType="$main.worksheet+xml"/>};
    }
    return $xml . '</Types>';
}

sub _core_xml ($self) {
    my $ts  = FIXED_TS;
    my $xml = _decl()
        . qq{<cp:coreProperties xmlns:cp="$NS_CP" xmlns:dc="$NS_DC" }
        . qq{xmlns:dcterms="$NS_DCTERMS" xmlns:xsi="$NS_XSI">}
        . qq{<dc:title>} . _esc($self->{title}) . '</dc:title>'
        . qq{<dc:creator>} . _esc($self->{author}) . '</dc:creator>';
    $xml .= '<dc:subject>' . _esc($self->{subject}) . '</dc:subject>'
        if defined $self->{subject} && length $self->{subject};
    $xml .= '<cp:keywords>' . _esc($self->{keywords}) . '</cp:keywords>'
        if defined $self->{keywords} && length $self->{keywords};
    $xml .= '<dc:description>' . _esc($self->{description}) . '</dc:description>'
        if defined $self->{description} && length $self->{description};
    $xml .= qq{<dcterms:created xsi:type="dcterms:W3CDTF">$ts</dcterms:created>}
        . qq{<dcterms:modified xsi:type="dcterms:W3CDTF">$ts</dcterms:modified>};
    return $xml . '</cp:coreProperties>';
}

sub _app_xml ($self) {
    return _decl() . qq{<Properties xmlns="$NS_EP" xmlns:vt="$NS_VT">}
        . '<Application>Amin</Application>'
        . '</Properties>';
}

# ── helpers ─────────────────────────────────────────────────────────────

sub _decl { qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n} }

sub _esc ($s) {
    $s = '' unless defined $s;
    $s =~ s/[^\x{09}\x{0A}\x{0D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]//g;
    $s =~ s/&/&amp;/g;
    $s =~ s/</&lt;/g;
    $s =~ s/>/&gt;/g;
    $s =~ s/"/&quot;/g;
    $s =~ s/'/&apos;/g;
    return $s;
}

sub _trim ($s) {
    $s = '' unless defined $s;
    $s =~ s/^\s+|\s+$//g;
    return $s;
}

sub _truth ($v) {
    return 0 unless defined $v;
    return 1 if $v =~ /^(?:1|true|yes|on)$/i;
    return 0;
}

sub _int_between ($v, $min, $max) {
    return undef unless defined $v && $v =~ /^\d+$/;
    return undef if $v < $min || $v > $max;
    return $v + 0;
}

sub _font_name ($v) {
    return 'Calibri' unless defined $v && length $v;
    $v =~ s/[^\w .-]//g;
    return length $v ? $v : 'Calibri';
}

sub _argb ($v) {
    return undef unless defined $v && length $v;
    (my $c = $v) =~ s/^#//;
    return uc "FF$c" if $c =~ /^[0-9A-Fa-f]{6}$/;
    return uc $c     if $c =~ /^[0-9A-Fa-f]{8}$/;
    return undef;
}

sub _is_number ($v) {
    return 0 unless defined $v;
    return $v =~ /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/ ? 1 : 0;
}

sub _excel_serial ($text) {
    return undef unless defined $text;
    my ($y, $mo, $d, $h, $mi, $s)
        = $text =~ /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?/;
    return undef unless defined $y;
    require Time::Local;
    my $epoch = eval { Time::Local::timegm($s // 0, $mi // 0, $h // 0,
                                           $d, $mo - 1, $y) };
    return undef unless defined $epoch;
    my $serial = $epoch / 86400 + 25569;
    my $out = sprintf '%.10f', $serial;
    $out =~ s/0+$//;
    $out =~ s/\.$//;
    return $out;
}

sub _split_ref ($ref) {
    return unless defined $ref && $ref =~ /^([A-Za-z]{1,3})(\d+)$/;
    my ($letters, $row) = (uc $1, $2 + 0);
    my $col = 0;
    $col = $col * 26 + (ord($_)-64) for split //, $letters;
    return unless $col >= 1 && $col <= MAX_COLS;
    return unless $row >= 1 && $row <= MAX_ROWS;
    return ($col, $row);
}

sub _num_to_col ($n) {
    my $s = '';
    while ($n > 0) {
        my $r = ($n - 1) % 26;
        $s = chr(65 + $r) . $s;
        $n = int(($n - 1) / 26);
    }
    return $s;
}

1;
