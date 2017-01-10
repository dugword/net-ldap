use v6;

use lib 'lib';

use Test;
use Net::LDAP;

constant ldap-server   = 'ldap.forumsys.com';
constant ldap-dn       = 'cn=read-only-admin,dc=example,dc=com';
constant ldap-password = 'password';

# Test 1
my $ldap = Net::LDAP.new(:host(ldap-server));
isa-ok $ldap, Net::LDAP, 'Create new LDAP object';

# Test 2
is $ldap.host, ldap-server, "Host is set to { ldap-server } ";

# Test 2
my %failed-bind-result = $ldap.bind(
    :dn(ldap-dn),
    :password('wrong'),
);
is %failed-bind-result<resultCode>, 49, 'Wrong password returns error code 49';

# Test 3
my %bind-result = $ldap.bind(
    :dn(ldap-dn),
    :password(ldap-password),
);
is %bind-result<resultCode>, 0, 'Correct password returns error code 0';

$ldap.search('(|(objectClass=person)(objectClass=user))');

done-testing;
