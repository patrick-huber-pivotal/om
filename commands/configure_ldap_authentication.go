package commands

import (
	"errors"
	"fmt"

	"github.com/pivotal-cf/jhanda"
	"github.com/pivotal-cf/om/api"
)

type ConfigureLDAPAuthentication struct {
	service configureAuthenticationService
	logger  logger
	Options struct {
		ConfigFile           string `long:"config"                short:"c"  description:"path to yml file for configuration (keys must match the following command line flags)"`
		DecryptionPassphrase string `long:"decryption-passphrase" short:"dp" required:"true" description:"passphrase used to encrypt the installation"`
		HTTPProxyURL         string `long:"http-proxy-url"                                   description:"proxy for outbound HTTP network traffic"`
		HTTPSProxyURL        string `long:"https-proxy-url"                                  description:"proxy for outbound HTTPS network traffic"`
		NoProxy              string `long:"no-proxy"                                         description:"comma-separated list of hosts that do not go through the proxy"`
		ServerURL            string `long:"ldap-server-url"                  required:"true" description:"The URL to the ldap server, must start with ldap:// or ldaps://"`
		Username             string `long:"ldap-username"                    required:"true" description:"The DN for the LDAP credentials used to search the directory. A valid LDAP ID that has read permissions to perform a search of the LDAP tree for user information"`
		Password             string `long:"ldap-password"                    required:"true" description:"Password credentials for the above DN to search the LDAP tree for user information"`
		UserSearchBase       string `long:"ldap-user-search-base"            required:"true" description:"Define a base at which the search starts e.g. 'ou=users,dc=mycompany,dc=com'"`
		UserSearchFilter     string `long:"ldap-user-search-filter"                          description:"The search filter used for the query. Takes one parameter, user ID defined as {0}. e.g. 'cn={0}'"`
		GroupSearchBase      string `long:"ldap-group-search-base"                           description:"Search start point for a user group membership search, and sequential nested searches."`
		GroupSearchFilter    string `long:"ldap-group-search-filter"                         description:"Search query filter to find the groups to which a user belongs"`
		Referrals            string `long:"ldap-referrals"                                   description:"Configures the UAA LDAP referral behavior. The following values are possible: follow, ignore, or throw"`
		ServerSSLCertificate string `long:"ldap-server-ssl-cert"                             description:"Path to ssl server certificate required when ldaps:// protocol is used."`
		RBACAdminGroup       string `long:"ldap-rbac-admin-group"            required:"true" description:"If LDAP is specified, please provide the admin group for your LDAP"`
		EmailAttribute       string `long:"ldap-email-attribute"             required:"true" description:"The name of the LDAP attribute that contains the users email address"`
	}
}

func NewConfigureLDAPAuthentication(service configureAuthenticationService, logger logger) ConfigureLDAPAuthentication {
	return ConfigureLDAPAuthentication{
		service: service,
		logger:  logger,
	}
}

func (ca ConfigureLDAPAuthentication) Execute(args []string) error {
	err := loadConfigFile(args, &ca.Options, nil)
	if err != nil {
		return fmt.Errorf("could not parse configure-ldap-authentication flags: %s", err)
	}

	ensureAvailabilityOutput, err := ca.service.EnsureAvailability(api.EnsureAvailabilityInput{})
	if err != nil {
		return fmt.Errorf("could not determine initial configuration status: %s", err)
	}

	if ensureAvailabilityOutput.Status == api.EnsureAvailabilityStatusUnknown {
		return errors.New("could not determine initial configuration status: received unexpected status")
	}

	if ensureAvailabilityOutput.Status != api.EnsureAvailabilityStatusUnstarted {
		ca.logger.Printf("configuration previously completed, skipping configuration")
		return nil
	}

	ca.logger.Printf("configuring LDAP authentication...")

	_, err = ca.service.Setup(api.SetupInput{
		IdentityProvider:                 "ldap",
		DecryptionPassphrase:             ca.Options.DecryptionPassphrase,
		DecryptionPassphraseConfirmation: ca.Options.DecryptionPassphrase,
		HTTPProxyURL:                     ca.Options.HTTPProxyURL,
		HTTPSProxyURL:                    ca.Options.HTTPSProxyURL,
		NoProxy:                          ca.Options.NoProxy,
		EULAAccepted:                     "true",
		LDAPSettings: api.LDAPSettings{
			ServerURL:          ca.Options.ServerURL,
			EmailAttribute:     ca.Options.EmailAttribute,
			GroupSearchBase:    ca.Options.GroupSearchBase,
			GroupSearchFilter:  ca.Options.GroupSearchFilter,
			UserSearchBase:     ca.Options.UserSearchBase,
			UserSearchFilter:   ca.Options.UserSearchFilter,
			Username:           ca.Options.Username,
			Password:           ca.Options.Password,
			Referrals:          ca.Options.Referrals,
			RBACAdminGroupName: ca.Options.RBACAdminGroup,
			ServerSSLCert:      ca.Options.ServerSSLCertificate,
		},
	})
	if err != nil {
		return fmt.Errorf("could not configure authentication: %s", err)
	}

	ca.logger.Printf("waiting for configuration to complete...")
	for ensureAvailabilityOutput.Status != api.EnsureAvailabilityStatusComplete {
		ensureAvailabilityOutput, err = ca.service.EnsureAvailability(api.EnsureAvailabilityInput{})
		if err != nil {
			return fmt.Errorf("could not determine final configuration status: %s", err)
		}
	}

	ca.logger.Printf("configuration complete")

	return nil
}

func (ca ConfigureLDAPAuthentication) Usage() jhanda.Usage {
	return jhanda.Usage{
		Description:      "This unauthenticated command helps setup the authentication mechanism for your Ops Manager with LDAP.",
		ShortDescription: "configures Ops Manager with LDAP authentication",
		Flags:            ca.Options,
	}
}
