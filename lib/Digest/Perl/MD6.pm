package Digest::Perl::MD6;

use strict;
use warnings;
use Data::Dumper;

require Exporter;
use List::Util 'max';

our @ISA       = qw(Exporter);
our @EXPORT_OK = qw(md6 md6_hex md6_base64);
our @EXPORT    = qw( );

our $VERSION = '0.01';

my ($b, $c, $n, $d, @K, $k, $r, $L, @M, $ell, @S0, @Sm, @Q, @t, @rs, @ls);

sub md6        { return pack 'C*', @{_prehash(@_)}; }
sub md6_hex    { _encode_hex(md6(@_))               }
sub md6_base64 { _encode_base64(md6(@_))            }

sub _prehash {
  my ($data, $size, $key, $levels) = @_;
  $data   //= '';
  $size   //= 256;
  $key    //= '';
  $levels //= 64;

  $data = bytes($data);
  $key  = bytes($key);

  $size = 1   if $size <= 0;
  $size = 512 if $size >  512;

  return _hash($data, $size, $key, $levels);
}

sub _hash {
  my ($data, $size, $key, $levels) = @_;

  $b = 512;
  $c = 128;
  $n = 89;
  $d = $size;
  @M = @{$data};
  @K = splice(@{$key}, 0, 64);
  $k = +@K;

  push(@K, 0x00) while (@K < 64);

  @K   = @{to_word(\@K)};

  $r   = max(($k ? 80 : 0), (40 + ($d / 4)));
  $L   = $levels;
  $ell = 0;
  @S0  = (0x01234567, 0x89abcdef);
  @Sm  = (0x7311c281, 0x2425cfa0);
  @Q   = (
    [0x7311c281, 0x2425cfa0], [0x64322864, 0x34aac8e7], [0xb60450e9, 0xef68b7c1],
    [0xe8fb2390, 0x8d9f06f1], [0xdd2e76cb, 0xa691e5bf], [0x0cd0d63b, 0x2c30bc41],
    [0x1f8ccf68, 0x23058f8a], [0x54e5ed5b, 0x88e3775d], [0x4ad12aae, 0x0a6d6031],
    [0x3e7f16bb, 0x88222e0d], [0x8af8671d, 0x3fb50c2c], [0x995ad117, 0x8bd25c31],
    [0xc878c1dd, 0x04c4b633], [0x3b72066c, 0x7a1552ac], [0x0d6f3522, 0x631effcb]
  );
  @t  = (17, 18, 21, 31, 67, 89);
  @rs = (10,  5, 13, 10, 11, 12,  2,  7, 14, 15,  7, 13, 11, 7, 6, 12);
  @ls = (11, 24,  9, 16, 15,  9, 27, 15,  6,  2, 29,  8, 15, 5, 31, 9);

  do {
    $ell += 1;
    @M = $ell > $L ? @{seq(\@M)} : @{par(\@M)};
  } while (@M != $c);

  return crop($d, \@M, 1);
}

sub par {
  my $M = shift;

  my $P = 0;
  my @B;
  my @C;
  my $z = @{$M} > $b ? 0 : 1;

  while(@{$M} < 1 || (@{$M} % $b) > 0) {
    push(@{$M}, 0x00);
    $P += 8;
  }

  $M = to_word($M);

  while(@{$M} > 0) {
    push(@B, [ @{$M}[0 .. ($b / 8)-1] ]);
    $M =     [ @{$M}[($b / 8) .. -1] ];
  }

  for (my $i = 0, my $p = 0, my $l = @B; $i < $l; $i += 1, $p = 0) {
    $p = ($i == (@B - 1)) ? $P : 0;
    push(@C, @{mid($B[$i], [], $i, $p, $z)});
  }

  return from_word(\@C);
}

sub seq {
  my $M = shift;

  my $P = 0;
  my @B;
  my @C = (
    [0x0, 0x0], [0x0, 0x0], [0x0, 0x0], [0x0, 0x0],
    [0x0, 0x0], [0x0, 0x0], [0x0, 0x0], [0x0, 0x0],
    [0x0, 0x0], [0x0, 0x0], [0x0, 0x0], [0x0, 0x0],
    [0x0, 0x0], [0x0, 0x0], [0x0, 0x0], [0x0, 0x0]
  );

  while(@{$M} < 1 || (@{$M} % ($b - $c)) > 0) {
    push(@{$M}, 0x00);
    $P += 8;
  }

  $M = to_word($M);

  while(@{$M} > 0) {
    push(@B, [ @{$M}[0 ..(($b - $c) / 8)-1] ]);
    $M =     [ @{$M}[(($b - $c) / 8)-1 .. -1] ];
  }

  my $z;
  for (my $i = 0, my $p = 0, my $l = @B; $i < $l; $i += 1, $p = 0) {
    $p = ($i == (@B - 1)) ? $P : 0;
    $z = ($i == (@B - 1)) ? 1  : 0;
    @C = @{mid($B[$i], \@C, $i, $p, $z)};
  }

  return from_word(\@C);
}

sub mid {
  my ($B, $C, $i, $p, $z) = @_;

  my @U = (
    (($ell & 0xff) << 24) | (($i / 0xffffffff) & 0xffffff),
    $i & 0xffffffff
  );

  my @V = (
    (($r & 0xfff)  << 16) |
    (($L & 0xff)   << 8)  |
    (($z & 0xf)    << 4)  |
    (($p & 0xf000) >> 12),
    (($p & 0xfff)  << 20) |
    (($k & 0xff)   << 12) |
    (($d & 0xfff))
  );

  return f([@Q, @K, \@U, \@V, @{$C}, @{$B}]);
}

sub f {
  my $N = shift;

  my @S = @S0;
  my @A = @{$N};

  my $x;
  for (my $j = 0, my $i = $n; $j < $r; $j += 1, $i += 16) {
    for (my $s = 0; $s < 16; $s += 1) {
			my $u = $i + $s;
      $x = [ @S ];
      #$x = _xor($x, $A[$i + $s - $t[5]]);
      #$x = _xor($x, $A[$i + $s - $t[0]]);
      #$x = _xor($x, _and($A[$i + $s - $t[1]], $A[$i + $s - $t[2]]));
      #$x = _xor($x, _and($A[$i + $s - $t[3]], $A[$i + $s - $t[4]]));
      $x = [$x->[0] ^ $A[$u - $t[5]]->[0], $x->[1] ^ $A[$u - $t[5]]->[1]];
      $x = [$x->[0] ^ $A[$u - $t[0]]->[0], $x->[1] ^ $A[$u - $t[0]]->[1]];
      $x = _xor($x, [$A[$u - $t[1]]->[0] & $A[$u - $t[2]]->[0], $A[$u - $t[1]]->[1] & $A[$u - $t[2]]->[1]]);
      $x = _xor($x, [$A[$u - $t[3]]->[0] & $A[$u - $t[4]]->[0], $A[$u - $t[3]]->[1] & $A[$u - $t[4]]->[1]]);

      $x = _xor($x, _shr($x, $rs[$s]));
      $A[$i + $s] = _xor($x, _shl($x, $ls[$s]));
    }

    @S = @{_xor(
      _xor(
        #_shl(\@S,  1),
        #_shr(\@S, 63)
				[(($S[0] << 1) | ($S[1] >> (32 - 1))) & 0xffffffff, ($S[1] << 1) & 0xffffffff],
        [0x00000000, $S[0] >> (63 - 32)]
      ),
      #_and(\@S, \@Sm)
			[$S[0] & $Sm[0], $S[1] & $Sm[1]]
    )};
  }

  return [ @A[@A-16 .. @A-1] ];
}

#sub _xor { my ($x, $y) = @_; return [$x->[0] ^ $y->[0], $x->[1] ^ $y->[1]]; }
#sub _and { my ($x, $y) = @_; return [$x->[0] & $y->[0], $x->[1] & $y->[1]]; }
sub _xor { return [$_[0]->[0] ^ $_[1]->[0], $_[0]->[1] ^ $_[1]->[1]]; }
sub _and { return [$_[0]->[0] & $_[1]->[0], $_[0]->[1] & $_[1]->[1]]; }

sub _shl {
  my ($x, $n) = @_;

  #my $a = $x->[0];
  #my $b = $x->[1];
  #
  #if ($n >= 32) { return [($b << ($n - 32)) & 0xffffffff, 0x00000000]; }
  #else          { return [(($a << $n) | ($b >> (32 - $n))) & 0xffffffff, ($b << $n) & 0xffffffff]; }
	if ($n >= 32) { return [($x->[1] << ($n - 32)) & 0xffffffff, 0x00000000]; }
  else          { return [(($x->[0] << $n) | ($x->[1] >> (32 - $n))) & 0xffffffff, ($x->[1] << $n) & 0xffffffff]; }
}

sub _shr {
  my ($x, $n) = @_;

  #my $a = $x->[0];
  #my $b = $x->[1];
  #
  #if ($n >= 32) { return [0x00000000, $a >> ($n - 32)]; }
  #else          { return [($a >> $n) & 0xffffffff, (($a << (32 - $n)) | ($b >> $n)) & 0xffffffff]; }
	if ($n >= 32) { return [0x00000000, $x->[0] >> ($n - 32)]; }
  else          { return [($x->[0] >> $n) & 0xffffffff, (($x->[0] << (32 - $n)) | ($x->[1] >> $n)) & 0xffffffff]; }
}

sub bytes {
  my $input = shift;

  my $length = length($input);
  my @output = unpack('C*', $input);

  return \@output;
}

sub to_word {
  my $input = shift;
	my @output;

  for(my $i = 0; $i < @{$input}; $i += 8) {
    push(@output, [
      (($input->[$i  ] << 24) | ($input->[$i+1] << 16) | ($input->[$i+2] << 8) | ($input->[$i+3])),
      (($input->[$i+4] << 24) | ($input->[$i+5] << 16) | ($input->[$i+6] << 8) | ($input->[$i+7]))
    ]);
  }

	return \@output;
}

sub from_word {
  my $input = shift;
  my @output;

  for (my $i = 0; $i < @{$input}; $i += 1) {
		#push(@output, (
		#	(($input->[$i][0] >> 24) & 0xff), (($input->[$i][0] >> 16) & 0xff), (($input->[$i][0] >>  8) & 0xff), (($input->[$i][0] >>  0) & 0xff),
		#	(($input->[$i][1] >> 24) & 0xff), (($input->[$i][1] >> 16) & 0xff), (($input->[$i][1] >>  8) & 0xff), (($input->[$i][1] >>  0) & 0xff)
		#));
		my ($x, $y) = @{$input->[$i]}[0, 1];
		push(@output, (
			(($x >> 24) & 0xff), (($x >> 16) & 0xff), (($x >> 8) & 0xff), (($x >> 0) & 0xff),
			(($y >> 24) & 0xff), (($y >> 16) & 0xff), (($y >> 8) & 0xff), (($y >> 0) & 0xff)
		));
  }

  return \@output;
}

sub _encode_hex { unpack 'H*', shift }
sub _encode_base64 {
	my $res;
	while ($_[0] =~ /(.{1,45})/gso) {
		$res .= substr pack('u', $1), 1;
		chop $res;
	}
	$res =~ tr|` -_|AA-Za-z0-9+/|;#`
	chop $res;
	$res
}

sub crop {
  my ($size, $hash, $right) = @_;
  $right //= 0;

  my $length = int(($size + 7) / 8);
  my $remain = $size % 8;

  if ($right) { $hash = [ @{$hash}[@{$hash} - $length .. @{$hash} - 1] ]; }
  else        { $hash = [ @{$hash}[0                  .. $length  - 1] ]; }

  $hash->[$length - 1] &= (0xff << (8 - $remain)) & 0xff if ($remain > 0);

  return $hash;
}

1;
__END__
=head1 NAME

Digest::Perl::MD6 - Perl implementation of MD6 Algorithm

=head1 VERSION

This document describes Digest::Perl::MD6 version 0.01

=head1 SYNOPSIS

  use Digest::MD6 qw(md6 md6_hex md6_base64);

  $digest = md6($data);
  $digest = md6_hex($data);
  $digest = md6_base64($data);

=head1 DESCRIPTION

This is a Perl implementation of the MD6 message-digest algorithm (see:
http://en.wikipedia.org/wiki/MD6) that does not depend on any other modules.

=head2 Methods

=over 4

=item * md6()

Returns the MD6 hash of the given string as a bytes.

=item * md6_hex()

Returns the MD6 hash of the given string as a hex string.

=item * md6_base64()

Returns the MD6 hash of the given string as a base64 string.

=back

=head1 AUTHOR

Sergey V. Kovalev, E<lt>info@neolite.ruE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2017 by Sergey V. Kovalev

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.22.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
