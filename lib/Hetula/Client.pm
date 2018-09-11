package Hetula::Client;

# ABSTRACT: Interface with Hetula
#
# Copyright 2018 National Library of Finland

=head1 NAME

Hetula::Client - Perl client implementation to communicate with Hetula.

=head1 DESCRIPTION

Perl client implementation to communicate with Hetula, the Patron data store

=head1 SYNOPSIS

 my $hc = Hetula::Client->new({baseURL => 'https://hetula.example.com'});

 my $loginResponse = $hc->login({username => 'master', password => 'blaster', organization => 'Administratoria'});
 die($loginResponse->{error}) if ($loginResponse->{error});

 my $loginActiveResp = $hc->loginActive();
 ok(! $loginActiveResp->{error}, "Login active");

 my $ssnAddResp = $hc->ssnAdd({ssn => 'bad-ssn'});
 ok($ssnAddResp->{error}, "SSN add failed - Bad SSN '$ssnAddResp->{error}'");

 my $ssnGetResp = $hc->ssnGet({id => 1});
 ok(! $ssnGetResp->{error}, "SSN got");

 my $ssnsBatchAddResp = $hc->ssnsBatchAdd(['101010-101A', '101010-102B']);
 is(@$ssnsBatchAddResp, 2, "SSNs batch add");

=cut

##Pragmas
use Modern::Perl;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Carp::Always;
use autodie;
use English; #Use verbose alternatives for perl's strange $0 and $\ etc.

##External modules
use Mojo::UserAgent;
use Storable;
use Regexp::Common;
use Data::Printer;

=head3 new

 @param1 {HASHRef} baseURL => https://hetula.example.com

=cut

sub new($class, $params) {
  die("Hetula::Client::BadParam - parameter 'baseURL' is missing") unless $params->{baseURL};
  die("Hetula::Client::BadParam - parameter 'baseURL' '$params->{baseURL}' is not a valid URI") unless $params->{baseURL} =~ /$RE{URI}{HTTP}{-scheme=>qr!https?!}/;

  my $s = bless(Storable::dclone($params), $class);

  $s->{ua} = Mojo::UserAgent->new() unless $s->{ua};
  return $s;
}

=head2 API Access methods

=head3 login

See Hetula API doc for endpoint POST /api/v1/auth

=cut

sub login($s, $params) {
  my $tx = $s->ua->post( $s->baseURL().'/api/v1/auth', {Accept => '*/*'}, json => $params );
  my $json = _handleResponse($tx);
  return $json if $json->{error};

  my $cookies = $tx->res->cookies;
  my $sessionCookie = $cookies->[0];
  $s->ua->cookie_jar->add($sessionCookie);

  my $csrfHeader = $tx->res->headers->header('X-CSRF-Token');

  $s->ua->on(start => sub {
    my ($ua, $tx) = @_;
    $tx->req->headers->header('X-CSRF-Token' => $csrfHeader);
  });

  return $json;
}

=head3 loginActive

=cut

sub loginActive($s) {
  my $tx = $s->ua->get( $s->baseURL().'/api/v1/auth' );
  return _handleResponse($tx);
}

=head3 ssnAdd

See Hetula API doc for endpoint POST /api/v1/ssns

=cut

sub ssnAdd($s, $params) {
  my $tx = $s->ua->post( $s->baseURL().'/api/v1/ssns', {Accept => '*/*'}, json => $params );
  return _handleResponse($tx);
}

=head3 ssnGet

See Hetula API doc for endpoint GET /api/v1/users/<id>

 @param1 {HASHRef} id => ssn id to get

=cut

sub ssnGet($s, $params) {
  die("Hetula::Class::BadParameter - parameter 'id' is not an integer") unless $params->{id} =~ /$RE{num}{int}/;
  my $tx = $s->ua->get( $s->baseURL().'/api/v1/ssns/'.$params->{id} );
  return _handleResponse($tx);
}

=head3 ssnsBatchAdd

See Hetula API doc for endpoint GET /api/v1/ssns/batch

 @param1 {ARRAYRef} of ssns

=cut

sub ssnsBatchAdd($s, $ssnArray) {
  my $tx = $s->ua->post( $s->baseURL().'/api/v1/ssns/batch', {Accept => '*/*'}, json => $ssnArray );
  return _handleResponse($tx);
}

=head3 userAdd

See Hetula API doc for endpoint POST /api/v1/users

=cut

sub userAdd($s, $params) {
  my $tx = $s->ua->post( $s->baseURL().'/api/v1/users', {Accept => '*/*'}, json => $params );
  return _handleResponse($tx);
}

=head3 userBasicAdd

Adds a user with only the most minimum permisions needed to push records into Hetula.
Organization the user belongs to is implied from the currently logged in organization.

 @param {HASHRef} username => 'MattiM',
                  password => 'Secret',
                  realname => 'Matti Meikäläinen',

=cut

sub userBasicAdd($s, $params) {
  $params->{permissions} = [
    'ssns-post',
    'auth-get',
  ];
  return $s->userAdd($params);
}

=head3 userReadAdd

Adds a user with read access to Hetula.
Organization the user belongs to is implied from the currently logged in organization.

 @param {HASHRef} username => 'MattiM',
                  password => 'Secret',
                  realname => 'Matti Meikäläinen',

=cut

sub userReadAdd($s, $params) {
  $params->{permissions} = [
    'ssns-post',
    'ssns-id-get',
    'auth-get',
  ];
  return $s->userAdd($params);
}

=head3 userMod

See Hetula API doc for endpoint PUT /api/v1/users/<id>

 @param {HASHRef} username or id => mandatory,
                  other patron attributes => and values,
                  ...

=cut

sub userMod($s, $params) {
  my $id = $params->{id} || $params->{username};
  die("Hetula::Class::BadParameter - parameter 'id' or 'username' is missing") unless ($id);
  my $tx = $s->ua->put( $s->baseURL()."/api/v1/users/$id", {Accept => '*/*'}, json => $params );
  return _handleResponse($tx);
}

=head3 userChangePassword

 @param {HASHRef} username or id => mandatory,
                  password => mandatory - the new password,

=cut

sub userChangePassword($s, $params) {
  my $id = $params->{id} || $params->{username};
  die("Hetula::Class::BadParameter - parameter 'id' or 'username' is missing") unless ($id);
  die("Hetula::Class::BadParameter - parameter 'password' is missing") unless $params->{password};
  my $tx = $s->ua->put( $s->baseURL()."/api/v1/users/$id/password", {Accept => '*/*'}, json => $params );
  return _handleResponse($tx);
}

=head3 userDisableAccount

To recover from a disabled account, change the password

 @param {String} username or id

=cut

sub userDisableAccount($s, $params) {
  my $id = $params->{id} || $params->{username};
  die("Hetula::Class::BadParameter - parameter 'id' or 'username' is missing") unless ($id);
  my $tx = $s->ua->delete( $s->baseURL()."/api/v1/users/$id/password", {Accept => '*/*'} );
  return _handleResponse($tx);
}

=head2 ATTRIBUTES

=head3 ua

=cut

sub ua { return $_[0]->{ua} }

=head3 baseURL

=cut

sub baseURL { return $_[0]->{baseURL} }

################
#######################
### Private methods ###
####################

sub _handleResponse($tx) {
  if (my $res = $tx->success) {
    if ($ENV{HETULA_DEBUG}) {
      print "Request success:\n";
      Data::Printer::p($res->json);
    }
    return $res->json;
  }
  else {
    my $error = $tx->error;
    $error->{error} = $tx->res->body || $error->{message} || $error->{code};
    if ($ENV{HETULA_DEBUG}) {
      print "Request error:\n";
      Data::Printer::p($error);
    }
    return $error;
  }
}

1;
