use v6;

use lib 'lib';

use Test;
use Net::LDAP::Filter;

constant test-filter = '(|(objectClass=person)(objectClass=user))';

# Test 1
my $filter = Net::LDAP::Filter.new;
isa-ok $filter, Net::LDAP::Filter, 'Filter is a Net::LDAP::Filter';

my $result = $filter.parse(test-filter);

dd $result;
