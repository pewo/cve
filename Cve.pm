package Object;

use strict;
use Carp;

our $VERSION = 'v0.0.1';

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
use Data::Dumper;
use Storable qw(lock_store lock_retrieve);
use POSIX;
use utf8;
use open ':encoding(utf8)';
use Sys::Hostname;
binmode(STDOUT, ":utf8");

our $DEBUG = 0;
our $VERSION = 'v0.1.0';
our @ISA = qw(Object);

sub new {
        my $proto = shift;
        my $class = ref($proto) || $proto;
        my $self  = {};
        bless($self,$class);

	my(%defaults) = ( 
		myhostname => hostname,
		home => "$ENV{HOME}",
		debug => $DEBUG,
	);
        my(%hash) = ( %defaults, @_) ;
	print Dumper(\%hash);
        while ( my($key,$val) = each(%hash) ) {
                $self->set($key,$val);
        }
	$self->set("debug",0);

	print Dumper(\$self) if ( $DEBUG );
        return($self);
}

sub debug() {
	my($self) = shift;
	my($level) = shift;
	my($str) = shift;
	
	my($debug) = $self->get("debug");
	if ( $level > 0 ) {
		return  unless ( $debug );
		return  unless ( $debug >= $level );
	}
	chomp($str);
	print "DEBUG($level): " . localtime(time) . " $str ***\n";
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
		return ($self->get($key));
	}
}
	

sub rpmbin { return ( shift->_accessor("rpmbin",shift) ); }
sub home { return ( shift->_accessor("home",shift) ); }
sub myhostname { return ( shift->_accessor("myhostname",shift) ); }

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
	return( $self->popen($cmd) );
}

sub deb_pkg_db() {
	my($self) = shift;
	my($cve_deb_db) = $self->home() . "/.cve-deb." . $self->hostname . ".db";
	$self->debug(5,"cve_deb_db: $cve_deb_db");

	my(%pkgcache) = $self->readhashcache($cve_deb_db);

	my($secs) = $pkgcache{secs} || 0;
	my($age) = time - $secs;
	if ( $age > 1600 ) {
		$self->debug(1,"Refreshing cache, age: $age");
		my(@pkg) = $self->_get_deb_pkg;
		$pkgcache{secs}=time;
		$pkgcache{data}=\@pkg;
		lock_store \%pkgcache, $cve_deb_db;
	}
	else {
		$self->debug(1, "Using cache...age=$age");
	}

	my($ap) = $pkgcache{data};
	return($ap);
}


	
sub rpm_pkg_db() {
	my($self) = shift;
	my($cve_rpm_db) = $self->home() . "/.cve-rpm." . $self->hostname . ".db";
	$self->debug(5,"cve_rpm_db: $cve_rpm_db");

	my(@pkg) = ();

	my(%rpmcache);
	if ( -r $cve_rpm_db ) {
		my($hashref);
		$hashref = lock_retrieve($cve_rpm_db);
		%rpmcache = %$hashref;
	}
	
	my($secs) = $rpmcache{secs} || 0;
	my($age) = time - $secs;
	if ( $age > 1600 ) {
		$self->debug(1,"Refreshing cache, age: $age");
		my(@pkg) = $self->rpm("-qa");
		$rpmcache{secs}=time;
		$rpmcache{data}=\@pkg;
		lock_store \%rpmcache, $cve_rpm_db;
	}
	else {
		$self->debug(1,"Using cache...age=$age");
	}

	my($ap) = $rpmcache{data};
	return($ap);
}

sub extract_cve() {
	my($self) = shift;
	my(@arr) = shift;

	my(@res) = ();
	foreach ( @arr ) {
		next unless ( $_ );
		if ( m/(CVE-\d\d\d\d-\d+)\D/ ) {
			push(@res,$1);
			print "CVE: $1\n";
		}
	}
	return(@res);
}

	
sub update_deb_cve_db() {
	my($self) = shift;

	my($ap) = $self->deb_pkg_db();

	# apt-get changelog openssh-server
	my($cve_changelog_db) = $self->home() . "/.cve-changelog." . $self->hostname . ".db";
	$self->debug(5,"cve_changelog_db: $cve_changelog_db");

	my(%cve) = $self->readhashcache($cve_changelog_db);

	my($pkg);
	foreach $pkg ( sort @$ap ) {
		my(@cve);
		if ( defined($cve{$pkg}) ) {
			$self->debug(9,"Using cache for $pkg");
			my($ap) = $cve{$pkg};
			@cve = @$ap;
		}
		else {
			my(@arr) = ();
			my($pkg_name,$pkg_version) = split(/\s+/,$pkg);
			$self->debug(9,"pkg_name=$pkg_name");
			$self->debug(9,"pkg_version=$pkg_version");
			my($changelog) = "/usr/share/doc/$pkg_name/changelog.Debian.gz";
			if ( -r $changelog ) {
				$self->debug(5,"Using changelog file $changelog");
				my($cmd) = "gunzip -c $changelog";
				@arr = $self->popen($cmd);
			}

			@cve = $self->extract_cve(@arr);
			if ( $#cve > 2 ) {
				print Dumper(\@cve);
				exit;
			}
			#$cve{$pkg} = \@cve;
			#print "Saving $cve_changelog_db\n";
			#lock_nstore(\%cve, $cve_changelog_db);
		}

		my($res) = undef;
		foreach ( @cve ) {
			next unless ( m/CVE/ );
			$res .= "$_ ";
		}
		if ( $res ) {
			print "$pkg: $res\n";
		}
	}
}

sub update_rpm_cve_db() {
	my($self) = shift;

	my($ap) = $self->rpm_pkg_db();

	my($cve_changelog_db) = $self->home() . "/.cve-changelog." . $self->hostname . ".db";
	$self->debug(5,"cve_changelog_db: $cve_changelog_db");
	my(%cve);
	if ( -r $cve_changelog_db ) {
		my($hashref);
		$hashref = lock_retrieve($cve_changelog_db);
		#print Dumper(\$hashref);
		%cve = %$hashref;
	}

	my($pkg);
	foreach $pkg ( sort @$ap ) {
		my(@cve);
		if ( defined($cve{$pkg}) ) {
			#print "Using cache...\n";
			my($ap) = $cve{$pkg};
			@cve = @$ap;
		}
		else {
			my(@arr) = $self->rpm("-q --changelog $pkg");
			foreach ( @arr ) {
				if ( m/(CVE-\d\d\d\d-\d+)\D/ ) {
					push(@cve,$1);
					print "Cve: $1\n";
				}
			}
			$cve{$pkg} = \@cve;
			print "Saving $cve_changelog_db\n";
			lock_nstore(\%cve, $cve_changelog_db);
		}

		my($res) = undef;
		foreach ( @cve ) {
			next unless ( m/CVE/ );
			$res .= "$_ ";
		}
		if ( $res ) {
			print "$pkg: $res\n";
		}
	}
}

sub update_cve_db() {
	my($self) = shift;
	
	my($do_deb) = 0;
	my($do_rpm) = 0;
	my($osrel) = "/etc/os-release";
	if ( -r $osrel ) {
		my(@osrel) = $self->readfile($osrel);
		foreach ( @osrel ) {
			if ( m/ubuntu|debian/i ) {
				$do_deb=1;
			}
			elsif ( m/rhel|centos|redhat|suse/ ) {
				$do_rpm=1;
			}
		}
	}
	if ( $do_deb ) {
		print "Using deb...\n";
		$self->update_deb_cve_db();
	}
	elsif ( $do_rpm ) {
		print "Using rpm...\n";
		$self->update_rpm_cve_db();
	}
}
	
1;
