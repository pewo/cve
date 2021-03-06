package Object;

#
# My old baseclasee for objetcs...
#
use strict;
use Carp;

our $VERSION = 'v0.1.0';

sub set($$$) {
        my($self) = shift;
        my($what) = shift;
        my($value) = shift;

        $what =~ tr/a-z/A-Z/;

        $self->{ $what }=$value;
        return($value);
}

sub get($$) {
        my($self) = shift;
        my($what) = shift;

        $what =~ tr/a-z/A-Z/;
        my $value = $self->{ $what };

        return($self->{ $what });
}

sub new {
        my $proto  = shift;
        my $class  = ref($proto) || $proto;
        my $self   = {};

        bless($self,$class);

        my(%args) = @_;

        my($key,$value);
        while( ($key, $value) = each %args ) {
                $key =~ tr/a-z/A-Z/;
                $self->set($key,$value);
        }

        return($self);
}

package Cve;

use strict;
use Carp;
use Storable qw(lock_store lock_retrieve);
use POSIX;
use utf8;
use open ':encoding(utf8)';
use Sys::Hostname;

my $dumper = eval {
	require Data::Dumper;
	Data::Dumper->import();
	1;
};

binmode(STDOUT, ":utf8");

our $DEBUG = 0;
our $VERSION = 'v0.1.0';
our @ISA = qw(Object);

our $ID = '$Id$';

sub new {
        my $proto = shift;
        my $class = ref($proto) || $proto;
        my $self  = {};
        bless($self,$class);

	my(%defaults) = ( 
		myhostname => hostname,
		debug => $DEBUG,
	);

        my(%hash) = ( %defaults, @_) ;
        while ( my($key,$val) = each(%hash) ) {
		if ( defined($val) ) {
                	$self->set($key,$val);
		}
        }
	unless ( $self->dbdir() ) {
		$self->dbdir($ENV{HOME});
	}
	$self->started(time);

	{
		my($do_deb) = 0;
		my($do_rpm) = 0;
		my($osrel) = "/etc/os-release";
		if ( -r $osrel ) {
			my(@osrel) = $self->readfile($osrel);
			foreach ( @osrel ) {
				if ( m/ubuntu|debian/i ) {
					$self->isdeb(1);
				}
				elsif ( m/rhel|centos|redhat|suse/ ) {
					$self->isrpm(1);
				}
			}
		}
		elsif ( -r "/etc/redhat-release" ) {
			$self->isrpm(1);
		}
		else {
			die "Cant find out if this is a deb or rpm based system, exiting...\n";
		}
	}

	$self->id($ID);
	my($cve_pkg_db) = $self->dbdir() . "/.cve-pkg." . $self->hostname . ".db";
	$self->pkgdb($cve_pkg_db);
	my($cve_changelog_db) = $self->dbdir() . "/.cve-cve." . $self->hostname . ".db";
	$self->cvedb($cve_changelog_db);

	$self->dumper($self) if ( $self->debuglvl() );
        return($self);
}

sub dumper() {
	my($self) = shift;
	my($var) = shift;
	
	if ( $dumper ) {
		print Dumper(\$var);
	}
}

sub debug() {
	my($self) = shift;
	my($level) = shift;
	my($str) = shift;
	
	chomp($str) if ( $str );
	my($debug) = $self->get("debug");
	if ( $level > 0 ) {
		return  unless ( $debug );
		return  unless ( $debug >= $level );
		my($p1,$f1,$line) = caller(0);
		my($p2, $f2, $l2, $subroutine) = caller(1);
		print "DEBUG($level) $subroutine/$line: " . localtime(time) . " $str ***\n";
	}
	else {
		print "$str\n";
	}
}

sub _accessor {
	my($self) = shift;
	my($key) = shift;
	my($value) = shift;
	if ( defined($value) ) {
		$self->debug(9,"Setting $key to $value");
		return ($self->set($key,$value));
	}
	else {
		my($value) = $self->get($key);
		my($str) = $value || "undef";
		$self->debug(9,"Returning $key value $str");
		return ($value);
	}
}
	

sub rpmbin { return ( shift->_accessor("rpmbin",shift) ); }
sub myhostname { return ( shift->_accessor("myhostname",shift) ); }
sub isrpm { return ( shift->_accessor("isrpm",shift) ); }
sub isdeb { return ( shift->_accessor("isdeb",shift) ); }
sub started { return ( shift->_accessor("started",shift) ); }
sub pkgdb { return ( shift->_accessor("pkgdb",shift) ); }
sub cvedb { return ( shift->_accessor("cvedb",shift) ); }
sub id { return ( shift->_accessor("id",shift) ); }
sub debuglvl { return ( shift->_accessor("debug",shift) ); }
sub dbdir { return ( shift->_accessor("dbdir",shift) ); }
sub force { return ( shift->_accessor("force",shift) ); }

sub trim {
	my($self) = shift;
	my($str) = shift;
	return($str) unless ( defined($str) );
	$str =~	s/#.*//;
	$str =~	s/^\s*//;
	$str =~	s/\s*$//;
	return($str);
}
	
sub popen() {
	my($self) = shift;
	my($cmd) = shift;
	my(@res) = ();
	if ( $cmd ) {
		$self->debug(5,"Executing: $cmd");
		unless ( open(POPEN,"$cmd |") ) {
			print "$cmd: $!\n";
			return(@res);
		}
		foreach ( <POPEN> ) {
			chomp;
			push(@res,$_);
		}
		close(POPEN);
	}
	return(@res);
}

sub rpm() {
	my($self) = shift;
	my($args) = shift || "--version";
	my($rpm) = $self->rpmbin();
	unless ( $rpm ) {
		$self->debug(1,"Trying to find rpm...");
		$rpm = "/bin/rpm" if ( -x "/bin/rpm" );
		$rpm = "/usr/bin/rpm" if ( -x "/usr/bin/rpm" );
		if ( $rpm ) {
			$self->debug(5,"Using $rpm as rpm");
			$self->rpmbin($rpm);
		}
		else {
			die "Unable to find executable rpm binary, exiting...\n";
		}
	}

	if ( $rpm ) {
		return ( $self->popen("$rpm $args") );
	}
}

sub readhashcache() {
	my($self) = shift;
	my($file) = shift;

	my(%hashcache) = ();
	if ( -r $file ) {
		$self->debug(5,"Reading $file into a hashref");
		my($hashref);
		$hashref = lock_retrieve($file);
		%hashcache = %$hashref;
	}
	return(%hashcache);
}

sub readfile() {
	my($self) = shift;
	my($file) = shift;
	my(@res) = ();

	if ( open(IN,"<$file") ) {
		$self->debug(5,"Reading $file into an array");
		foreach ( <IN> ) {
			next unless ( $_ );
			chomp;
			push(@res,$_);
		}
		close(IN);
	}
	else {
		print "Reading $file: $!\n";
	}
	return(@res);
}
	
sub _get_deb_pkg() {
	my($self) = shift;
	my($cmd) = "dpkg-query -W -f \'\${Package} \${Version}\\n\'";
	$self->debug(9,"Retreiving deb pkg list");
	return( $self->popen($cmd) );
}

sub _get_rpm_pkg() {
	my($self) = shift;
	$self->debug(9,"Retreiving rpm pkg list");
	return( $self->rpm("-qa") ) ;
}

sub pkg_db() {
	my($self) = shift;
	my(%args) = @_;
	my($cve_pkg_db) = $self->pkgdb();
	$self->debug(5,"cve_pkg_db: $cve_pkg_db");

	my(@pkg) = ();

	my(%pkgcache) = $self->readhashcache($cve_pkg_db);

	my($secs) = $pkgcache{TIME} || 0;
	
	my($age) = time - $secs;
	if ( $age > 1600 || $args{force} ) {
		$self->debug(0,"Refreshing pkg db");
		$self->debug(1,"Refreshing cache, age: $age");
		my(@pkg) = ();
		if ( $self->isrpm() ) {
			@pkg = $self->_get_rpm_pkg();
		}
		elsif ( $self->isdeb() ) {
			@pkg = $self->_get_deb_pkg();
		}
		$pkgcache{TIME}=time;
		$pkgcache{DATA}=\@pkg;
		lock_store \%pkgcache, $cve_pkg_db;
	}
	else {
		$self->debug(0,"Using pkg db cache");
	}

	my($ap) = $pkgcache{DATA};
	return($ap);
}

sub extract_cve() {
	my($self) = shift;
	my(@arr) = @_;

	my(@res) = ();
	$self->debug(9,"Extracting CVE from input");
	foreach ( @arr ) {
		next unless ( $_ );
		if ( m/(CVE-\d\d\d\d-\d+)\D/ ) {
			push(@res,$1);
		}
	}
	return(@res);
}

	
sub update_cve_db() {
	my($self) = shift;
	my(%args) = @_;

	my($started) = $self->started();
	my($ap) = $self->pkg_db( force => $args{force} );
	my(@pkg) = @$ap;

	# apt-get changelog openssh-server
	my($cve_cve_db) = $self->cvedb();
	$self->debug(5,"cve_cvedb: $cve_cve_db");

	my(%cve) = $self->readhashcache($cve_cve_db);

	my($pkg);
	my($max) = 0;
	my($refresh) = 0;
	my($pkgs) = $#pkg + 1;
	my($index) = 0;
	foreach $pkg ( sort @pkg ) {
		$index++;
		if ( $max-- == 1 ) {
			print "Exiting, because you are debugging...\n";
			exit(1);
		}
		my(@cve);
		if ( defined($cve{$pkg}{DATA}) ) {
			$self->debug(9,"Using cache for $pkg");
			my($ap) = $cve{$pkg}{DATA};
			@cve = @$ap;
			$self->debug(0,"Checking $index/$pkgs $pkg (cached)");
		}
		else {
			$self->debug(0,"Checking $index/$pkgs $pkg");
			$self->debug(9,"Refreshing $pkg CVE cache");
			my(@arr) = ();
			if ( $self->isdeb() ) {
				my($pkg_name,$pkg_version) = split(/\s+/,$pkg);
				$self->debug(9,"pkg_name=$pkg_name");
				$self->debug(9,"pkg_version=$pkg_version");
				my($changelog) = "/usr/share/doc/$pkg_name/changelog.Debian.gz";
				if ( -r $changelog ) {
					$self->debug(5,"Using changelog file $changelog");
					my($cmd) = "gunzip -c $changelog";
					@arr = $self->popen($cmd);
				}
				else {
					my($cmd) = "apt-get changelog $pkg_name";
					$self->debug(5,"Using apt-get to get changelog");
					@arr = $self->popen($cmd);
				}
			}
			elsif ( $self->isrpm() ) {
				@arr = $self->rpm("-q --changelog $pkg");
			}

			@cve = $self->extract_cve(@arr);
			$cve{$pkg}{DATA} = \@cve;
			$cve{$pkg}{TIME} = $started;
			$refresh++;
		}
	}
	if ( $refresh ) {
		print "Refreshing CVE db $cve_cve_db\n";
		lock_store(\%cve, $cve_cve_db);
	}
}

sub dump_cve_db() {
	my($self) = shift;
	my(%args) = @_;

	my($cve_cve_db) = $self->cvedb();
	my(%cve) = $self->readhashcache($cve_cve_db);
	my($pkg);
	my($pkgs) = 0;
	if ( $args{latest} ) {
		my($latest) = 0;
		my(%allcve) = %cve;
		%cve = ();
		foreach $pkg ( sort keys %allcve ) {
			if ( $latest < $allcve{$pkg}{TIME} ) {
				$latest = $allcve{$pkg}{TIME};
				$self->debug(5,"Latest = $latest, " . localtime($latest));
			}
		}
		foreach $pkg ( sort keys %allcve ) {
			next unless ( $allcve{$pkg}{TIME} == $latest );
			$cve{$pkg}=$allcve{$pkg};
		}
	}
		
	foreach $pkg ( sort keys %cve ) {
		$pkgs++;
		my($ap) = $cve{$pkg}{DATA};
		my($time) = $cve{$pkg}{TIME};
		my(@arr) = @$ap;

		#
		# Split in to ~1000 characters / line
		#
		my(@res) = ();
		my($rec) = 0;
		my($len) = 0;
		foreach ( @arr ) {
			if ( $len > 1000 ) {
				$rec++;
				$len=0;
			}
			my($str) = "$_ ";
			$res[$rec] .= $str;
			$len += length($str);
		}
				
		#
		# Print all record 
		#
		$rec = 0;
		my($recs) = $#res + 1;
		foreach ( @res ) {
			$rec++;
			print "$pkg ($time) $rec/$recs: $_\n";
		}
					
	}
	unless ( $pkgs ) {
		print "No records in CVE db ($cve_cve_db), maybe do an update first...\n";
	}
}
	
sub search_cve_db() {
	my($self) = shift;
	my($search) = shift;
	
	return() unless ( defined($search) );
	return() unless ( $search );

	my($ap) = $self->pkg_db();

	my($cve_cve_db) = $self->cvedb();
	$self->debug(5,"cve_cve_db: $cve_cve_db");
	my(%cve) = $self->readhashcache($cve_cve_db);

	my($pkg);
	my(%res);
	foreach $pkg ( @$ap ) {
		my($cveap) = $cve{$pkg}{DATA};
		my($foundcve) = 0;
		foreach ( @$cveap ) {
			if ( $_ =~ /$search/i ) {
				$foundcve++;
				$res{$pkg} .= $_ . " ";
			}
		}
		unless ( $foundcve ) {
			if ( $pkg =~ /$search/i ) {
				$res{$pkg}=join(" ",@$cveap);
			}
		}
	}
	foreach $pkg ( sort keys %res ) {
		print "$pkg: $res{$pkg}\n";
	}
}
	
1;
