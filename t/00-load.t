#!/usr/bin/env perl
use FindBin;
use lib "$FindBin::Bin/../lib";

use Test::Most;

use File::Find;


ok(1, "Scenario: Find all .pl and .pm -files and check if they actually compile");

#Find files in the usual places
my $searchDir = "$FindBin::Bin/../lib/";
File::Find::find( \&testLib, $searchDir );

testBin("$FindBin::Bin/../bin/hetula-client");


sub testLib {
  my ($filename) = @_;
  $filename = $File::Find::name unless $filename;

  return unless $filename =~ m/\.p[ml]$/;

  require_ok($filename);
}

sub testBin {
  my ($filename) = @_;
  `perl -cw -I$searchDir $filename`;
  my $exitCode = ${^CHILD_ERROR_NATIVE} >> 8;
  ok(not($exitCode), "$filename");
}

done_testing();
