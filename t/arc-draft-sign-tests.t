#!/usr/bin/env perl

use strict;
use warnings;

use Data::Dumper;
use Test::More;

use lib 't';

use ArcTestSuite;

my $Tests = ArcTestSuite->new();

$Tests->LoadFile( 't/arc-draft-sign-tests.yml' );
$Tests->SetOperation( 'sign' );
$Tests->RunAllScenarios();

done_testing();

#print Dumper( $Tests->{ 'tests' } );

