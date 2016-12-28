use v6;

constant LDAP_SUCCESS is export(:LDAP_SUCCESS) = 0;
constant LDAP_OPERATIONS_ERROR is export(:LDAP_OPERATIONS_ERROR) = 1;
constant LDAP_PROTOCOL_ERROR is export(:LDAP_PROTOCOL_ERROR) = 2;
constant LDAP_TIMELIMIT_EXCEEDED is export(:LDAP_TIMELIMIT_EXCEEDED) = 3;
constant LDAP_SIZELIMIT_EXCEEDED is export(:LDAP_SIZELIMIT_EXCEEDED) = 4;
constant LDAP_COMPARE_FALSE is export(:LDAP_COMPARE_FALSE) = 5;
constant LDAP_COMPARE_TRUE is export(:LDAP_COMPARE_TRUE) = 6;
constant LDAP_AUTH_METHOD_NOT_SUPPORTED is export(:LDAP_AUTH_METHOD_NOT_SUPPORTED) = 7;
constant LDAP_STRONG_AUTH_NOT_SUPPORTED is export(:LDAP_STRONG_AUTH_NOT_SUPPORTED) = 7;
constant LDAP_STRONG_AUTH_REQUIRED is export(:LDAP_STRONG_AUTH_REQUIRED) = 8;
constant LDAP_PARTIAL_RESULTS is export(:LDAP_PARTIAL_RESULTS) = 9;
constant LDAP_REFERRAL is export(:LDAP_REFERRAL) = 10;
constant LDAP_ADMIN_LIMIT_EXCEEDED is export(:LDAP_ADMIN_LIMIT_EXCEEDED) = 11;
constant LDAP_UNAVAILABLE_CRITICAL_EXT is export(:LDAP_UNAVAILABLE_CRITICAL_EXT) = 12;
constant LDAP_CONFIDENTIALITY_REQUIRED is export(:LDAP_CONFIDENTIALITY_REQUIRED) = 13;
constant LDAP_SASL_BIND_IN_PROGRESS is export(:LDAP_SASL_BIND_IN_PROGRESS) = 14;
constant LDAP_NO_SUCH_ATTRIBUTE is export(:LDAP_NO_SUCH_ATTRIBUTE) = 16;
constant LDAP_UNDEFINED_TYPE is export(:LDAP_UNDEFINED_TYPE) = 17;
constant LDAP_INAPPROPRIATE_MATCHING is export(:LDAP_INAPPROPRIATE_MATCHING) = 18;
constant LDAP_CONSTRAINT_VIOLATION is export(:LDAP_CONSTRAINT_VIOLATION) = 19;
constant LDAP_TYPE_OR_VALUE_EXISTS is export(:LDAP_TYPE_OR_VALUE_EXISTS) = 20;
constant LDAP_INVALID_SYNTAX is export(:LDAP_INVALID_SYNTAX) = 21;
constant LDAP_NO_SUCH_OBJECT is export(:LDAP_NO_SUCH_OBJECT) = 32;
constant LDAP_ALIAS_PROBLEM is export(:LDAP_ALIAS_PROBLEM) = 33;
constant LDAP_INVALID_DN_SYNTAX is export(:LDAP_INVALID_DN_SYNTAX) = 34;
constant LDAP_IS_LEAF is export(:LDAP_IS_LEAF) = 35;
constant LDAP_ALIAS_DEREF_PROBLEM is export(:LDAP_ALIAS_DEREF_PROBLEM) = 36;
constant LDAP_PROXY_AUTHZ_FAILURE is export(:LDAP_PROXY_AUTHZ_FAILURE) = 47;
constant LDAP_INAPPROPRIATE_AUTH is export(:LDAP_INAPPROPRIATE_AUTH) = 48;
constant LDAP_INVALID_CREDENTIALS is export(:LDAP_INVALID_CREDENTIALS) = 49;
constant LDAP_INSUFFICIENT_ACCESS is export(:LDAP_INSUFFICIENT_ACCESS) = 50;
constant LDAP_BUSY is export(:LDAP_BUSY) = 51;
constant LDAP_UNAVAILABLE is export(:LDAP_UNAVAILABLE) = 52;
constant LDAP_UNWILLING_TO_PERFORM is export(:LDAP_UNWILLING_TO_PERFORM) = 53;
constant LDAP_LOOP_DETECT is export(:LDAP_LOOP_DETECT) = 54;
constant LDAP_SORT_CONTROL_MISSING is export(:LDAP_SORT_CONTROL_MISSING) = 60;
constant LDAP_INDEX_RANGE_ERROR is export(:LDAP_INDEX_RANGE_ERROR) = 61;
constant LDAP_NAMING_VIOLATION is export(:LDAP_NAMING_VIOLATION) = 64;
constant LDAP_OBJECT_CLASS_VIOLATION is export(:LDAP_OBJECT_CLASS_VIOLATION) = 65;
constant LDAP_NOT_ALLOWED_ON_NONLEAF is export(:LDAP_NOT_ALLOWED_ON_NONLEAF) = 66;
constant LDAP_NOT_ALLOWED_ON_RDN is export(:LDAP_NOT_ALLOWED_ON_RDN) = 67;
constant LDAP_ALREADY_EXISTS is export(:LDAP_ALREADY_EXISTS) = 68;
constant LDAP_NO_OBJECT_CLASS_MODS is export(:LDAP_NO_OBJECT_CLASS_MODS) = 69;
constant LDAP_RESULTS_TOO_LARGE is export(:LDAP_RESULTS_TOO_LARGE) = 70;
constant LDAP_AFFECTS_MULTIPLE_DSAS is export(:LDAP_AFFECTS_MULTIPLE_DSAS) = 71;
constant LDAP_VLV_ERROR is export(:LDAP_VLV_ERROR) = 76;
constant LDAP_OTHER is export(:LDAP_OTHER) = 80;
constant LDAP_SERVER_DOWN is export(:LDAP_SERVER_DOWN) = 81;
constant LDAP_LOCAL_ERROR is export(:LDAP_LOCAL_ERROR) = 82;
constant LDAP_ENCODING_ERROR is export(:LDAP_ENCODING_ERROR) = 83;
constant LDAP_DECODING_ERROR is export(:LDAP_DECODING_ERROR) = 84;
constant LDAP_TIMEOUT is export(:LDAP_TIMEOUT) = 85;
constant LDAP_AUTH_UNKNOWN is export(:LDAP_AUTH_UNKNOWN) = 86;
constant LDAP_FILTER_ERROR is export(:LDAP_FILTER_ERROR) = 87;
constant LDAP_USER_CANCELED is export(:LDAP_USER_CANCELED) = 88;
constant LDAP_PARAM_ERROR is export(:LDAP_PARAM_ERROR) = 89;
constant LDAP_NO_MEMORY is export(:LDAP_NO_MEMORY) = 90;
constant LDAP_CONNECT_ERROR is export(:LDAP_CONNECT_ERROR) = 91;
constant LDAP_NOT_SUPPORTED is export(:LDAP_NOT_SUPPORTED) = 92;
constant LDAP_CONTROL_NOT_FOUND is export(:LDAP_CONTROL_NOT_FOUND) = 93;
constant LDAP_NO_RESULTS_RETURNED is export(:LDAP_NO_RESULTS_RETURNED) = 94;
constant LDAP_MORE_RESULTS_TO_RETURN is export(:LDAP_MORE_RESULTS_TO_RETURN) = 95;
constant LDAP_CLIENT_LOOP is export(:LDAP_CLIENT_LOOP) = 96;
constant LDAP_REFERRAL_LIMIT_EXCEEDED is export(:LDAP_REFERRAL_LIMIT_EXCEEDED) = 97;
constant LDAP_CANCELED is export(:LDAP_CANCELED) = 118;
constant LDAP_NO_SUCH_OPERATION is export(:LDAP_NO_SUCH_OPERATION) = 119;
constant LDAP_TOO_LATE is export(:LDAP_TOO_LATE) = 120;
constant LDAP_CANNOT_CANCEL is export(:LDAP_CANNOT_CANCEL) = 121;
constant LDAP_ASSERTION_FAILED is export(:LDAP_ASSERTION_FAILED) = 122;
constant LDAP_SYNC_REFRESH_REQUIRED is export(:LDAP_SYNC_REFRESH_REQUIRED) = 4096;

=begin old



local $_;

# These subs are really in Net::LDAP::Util, but need to access <DATA>
# so its easier for them to be here.


sub Net::LDAP::Util::ldap_error_name {
  my $code = 0 + (ref($_[0]) ? $_[0]->code : $_[0]);

  $err2name[$code] || sprintf('LDAP error code %d(0x%02X)', $code, $code);
}


sub Net::LDAP::Util::ldap_error_text {
  my $code = 0 + (ref($_[0]) ? $_[0]->code : $_[0]);
  my $text;

  seek(DATA, 0, 0);
  local $/=''; # paragraph mode
  local $_;
  my $n = -1;
  while (<DATA>) {
    last  if /^=head2/ and ++$n;
    last  if /^=cut/;
    next  if $n;
    if (/^=item\s+(LDAP_\S+)\s+\((\d+)\)/) {
      last  if defined $text;
      $text = ''  if $2 == $code;
    }
    elsif (defined $text) {
      $text .= $_;
    }
  }

  if (defined $text) {
    # Do some cleanup. Really should use a proper pod parser here.

    $text =~ s/^=item\s+\*\s+/ * /msg;
    $text =~ s/^=(over\s*\d*|back)//msg;
    $text =~ s/ +\n//g;
    $text =~ s/\n\n+/\n\n/g;
    $text =~ s/\n+\Z/\n/  if defined $text;
  }

  return $text;
}

1;

__DATA__
See original file

=end old
