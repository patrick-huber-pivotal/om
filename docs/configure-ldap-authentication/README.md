&larr; [back to Commands](../README.md)

# `om configure-ldap-authentication`

The `configure-ldap-authentication` command will allow you to setup your user account on the Ops Manager with LDAP authentication.

To set up your Ops Manager with internal authentication instead, use `configure-authentication`.

## Command Usage
```
Usage: om [options] configure-ldap-authentication [<args>]
ॐ  configure-ldap-authentication
This unauthenticated command helps setup the authentication mechanism for your Ops Manager with LDAP.

Usage: om [options] configure-ldap-authentication [<args>]
  --client-id, -c, OM_CLIENT_ID                          string  Client ID for the Ops Manager VM (not required for unauthenticated commands)
  --client-secret, -s, OM_CLIENT_SECRET                  string  Client Secret for the Ops Manager VM (not required for unauthenticated commands)
  --connect-timeout, -o                                  int     timeout in seconds to make TCP connections (default: 5)
  --decryption-passphrase, -d, OM_DECRYPTION_PASSPHRASE  string  Passphrase to decrypt the installation if the Ops Manager VM has been rebooted (optional for most commands)
  --env, -e                                              string  env file with login credentials
  --help, -h                                             bool    prints this usage information (default: false)
  --password, -p, OM_PASSWORD                            string  admin password for the Ops Manager VM (not required for unauthenticated commands)
  --request-timeout, -r                                  int     timeout in seconds for HTTP requests to Ops Manager (default: 1800)
  --skip-ssl-validation, -k                              bool    skip ssl certificate validation during http requests (default: false)
  --target, -t, OM_TARGET                                string  location of the Ops Manager VM
  --trace, -tr                                           bool    prints HTTP requests and response payloads
  --username, -u, OM_USERNAME                            string  admin username for the Ops Manager VM (not required for unauthenticated commands)
  --version, -v                                          bool    prints the om release version (default: false)

Command Arguments:
  --config, -c                  string             path to yml file for configuration (keys must match the following command line flags)
  --decryption-passphrase, -dp  string (required)  passphrase used to encrypt the installation
  --http-proxy-url              string             proxy for outbound HTTP network traffic
  --https-proxy-url             string             proxy for outbound HTTPS network traffic
  --ldap-email-attribute        string (required)  The name of the LDAP attribute that contains the users email address
  --ldap-group-search-base      string             Search start point for a user group membership search, and sequential nested searches.
  --ldap-group-search-filter    string             Search query filter to find the groups to which a user belongs
  --ldap-password               string (required)  Password credentials for the above DN to search the LDAP tree for user information
  --ldap-rbac-admin-group       string (required)  If LDAP is specified, please provide the admin group for your LDAP
  --ldap-referrals              string             Configures the UAA LDAP referral behavior. The following values are possible: follow, ignore, or throw
  --ldap-server-ssl-cert        string             Path to ssl server certificate required when ldaps:// protocol is used.
  --ldap-server-url             string (required)  The URL to the ldap server, must start with ldap:// or ldaps://. e.g. ldap://localhost:389 or ldaps://secure.host:636
  --ldap-user-search-base       string (required)  Define a base at which the search starts e.g. 'ou=users,dc=mycompany,dc=com'
  --ldap-user-search-filter     string             The search filter used for the query. Takes one parameter, user ID defined as {0}. e.g. 'cn={0}'
  --ldap-username               string (required)  The DN for the LDAP credentials used to search the directory. A valid LDAP ID that has read permissions to perform a search of the LDAP tree for user information.
  --no-proxy                    string             comma-separated list of hosts that do not go through the proxy
```