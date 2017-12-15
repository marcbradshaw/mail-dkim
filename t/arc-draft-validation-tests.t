#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;

use lib 't';

plan tests => 168; # number of tests currently in the validation yaml, not counting the sha1 tests

my $nskip = 0;
$nskip = $ARGV[0] if @ARGV > 0;

use ArcTestSuite;

my $Tests = new ArcTestSuite;

$Tests->LoadFile( 't/arc_test_suite/arc-draft-validation-tests.yml' );
$Tests->SetOperation( 'validate' );
$Tests->RunAllScenarios($nskip);

done_testing();
