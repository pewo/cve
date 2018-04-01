#!/usr/bin/perl -w

use strict;
use Getopt::Long;
use Pod::Usage;
use FindBin;
use lib $FindBin::Bin;

eval {
	require Cve;
	1;
};

if ( $@ ) {
	print "Unable to load Cve module\n";
	print "On some system you need to install perl-open\n\n";
	print $@ . "\n";
	exit(1);
}

my($ID) = '$Id$';

my($debug) = 0;
my($update) = undef;
my($dump) = undef;
my($search) = undef;
my($help) = undef;
my($dbdir) = undef;
my($latest) = undef;
my($force) = undef;

sub help() {
	print "$0 arguments\n";
	print "  --dbdir=<db dir>  Where outputfiles are stored\n";
	print "  --debug=<level> Set debug level\n";
	print "  --dump  Dump the CVE database\n";
	print "  --force  force update on pkg db (ignoring cache)\n";
	print "  --help This output\n";
	print "  --latest  Used togehter with dump to onbly dump tha latest updates\n";
	print "  --search=text Search the CVE db\n";
	print "  --update Update the CVE db\n";
	return(0);
}

GetOptions (
	"dbdir=s" => \$dbdir,
	"debug=i"  => \$debug,
	"d|dump"  => \$dump,
	"force"  => \$force,
	"h|help"  => \$help,
	"latest" => \$latest,
	"s|search=s" => \$search,
	"u|update" => \$update,
) or die("Error in command line arguments\n");

foreach ( @ARGV ) {
	if ( defined($search) ) {
		$search .= " ";
	}
	$search .= $_;
}

if ( $help ) {
	exit(help());
}

my($cve) = new Cve( debug => $debug, dbdir => $dbdir );

my($done) = 0;

if ( $update ) {
	$done++;
	$cve->update_cve_db( force => $force );
}

if ( $dump ) {
	$done++;
	$cve->dump_cve_db( latest => $latest );
}

if ( $search ) {
	$done++;
	$cve->search_cve_db($search);
}

unless ( $done ) {
	exit(help());
}

