#!/usr/bin/perl -w

use strict;
use Storable qw(lock_store lock_retrieve);
use Data::Dumper;

foreach ( @ARGV ) {
	if ( -r $_ ) {
		my($hp) = lock_retrieve($_);
		print Dumper(\$hp);
	}
}

	
