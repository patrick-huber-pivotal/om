package commands_test

import (
	"errors"
	"fmt"

	"github.com/pivotal-cf/jhanda"
	"github.com/pivotal-cf/om/api"
	"github.com/pivotal-cf/om/commands"
	"github.com/pivotal-cf/om/commands/fakes"

	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConfigureLDAPAuthentication", func() {
	Describe("Execute", func() {
		It("configures LDAP authentication", func() {
			service := &fakes.ConfigureAuthenticationService{}
			eaOutputs := []api.EnsureAvailabilityOutput{
				{Status: api.EnsureAvailabilityStatusUnstarted},
				{Status: api.EnsureAvailabilityStatusPending},
				{Status: api.EnsureAvailabilityStatusPending},
				{Status: api.EnsureAvailabilityStatusComplete},
			}

			service.EnsureAvailabilityStub = func(api.EnsureAvailabilityInput) (api.EnsureAvailabilityOutput, error) {
				return eaOutputs[service.EnsureAvailabilityCallCount()-1], nil
			}

			logger := &fakes.Logger{}

			command := commands.NewConfigureLDAPAuthentication(service, logger)
			err := command.Execute([]string{
				"--decryption-passphrase", "some-passphrase",
				"--ldap-server-url", "ldap://ldap.example.com:389",
				"--ldap-username", "username",
				"--ldap-password", "password",
				"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
				"--ldap-user-search-filter", "cn={0}",
				"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
				"--ldap-group-search-filter", "member={0}",
				"--ldap-referrals", "follow",
				"--ldap-server-ssl-cert", "/path/to/certificate",
				"--ldap-rbac-admin-group", "admin",
				"--ldap-email-attribute", "mail",
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(service.SetupArgsForCall(0)).To(Equal(api.SetupInput{
				IdentityProvider:                 "ldap",
				DecryptionPassphrase:             "some-passphrase",
				DecryptionPassphraseConfirmation: "some-passphrase",
				EULAAccepted:                     "true",
				LDAPSettings: api.LDAPSettings{
					ServerURL:          "ldap://ldap.example.com:389",
					EmailAttribute:     "mail",
					GroupSearchBase:    "ou=groups,dc=mycompany,dc=com",
					GroupSearchFilter:  "member={0}",
					UserSearchBase:     "ou=users,dc=mycompany,dc=com",
					UserSearchFilter:   "cn={0}",
					Username:           "username",
					Password:           "password",
					Referrals:          "follow",
					RBACAdminGroupName: "admin",
					ServerSSLCert:      "/path/to/certificate",
				},
			}))

			Expect(service.EnsureAvailabilityCallCount()).To(Equal(4))

			format, content := logger.PrintfArgsForCall(0)
			Expect(fmt.Sprintf(format, content...)).To(Equal("configuring LDAP authentication..."))

			format, content = logger.PrintfArgsForCall(1)
			Expect(fmt.Sprintf(format, content...)).To(Equal("waiting for configuration to complete..."))

			format, content = logger.PrintfArgsForCall(2)
			Expect(fmt.Sprintf(format, content...)).To(Equal("configuration complete"))
		})

		Context("when the authentication setup has already been configured", func() {
			It("returns without configuring the authentication system", func() {
				service := &fakes.ConfigureAuthenticationService{}
				service.EnsureAvailabilityReturns(api.EnsureAvailabilityOutput{
					Status: api.EnsureAvailabilityStatusComplete,
				}, nil)

				logger := &fakes.Logger{}

				command := commands.NewConfigureLDAPAuthentication(service, logger)
				err := command.Execute([]string{
					"--decryption-passphrase", "some-passphrase",
					"--ldap-server-url", "ldap://ldap.example.com:389",
					"--ldap-username", "username",
					"--ldap-password", "password",
					"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
					"--ldap-user-search-filter", "cn={0}",
					"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
					"--ldap-group-search-filter", "member={0}",
					"--ldap-referrals", "follow",
					"--ldap-server-ssl-cert", "/path/to/certificate",
					"--ldap-rbac-admin-group", "admin",
					"--ldap-email-attribute", "mail",
				})
				Expect(err).NotTo(HaveOccurred())

				Expect(service.EnsureAvailabilityCallCount()).To(Equal(1))
				Expect(service.SetupCallCount()).To(Equal(0))

				format, content := logger.PrintfArgsForCall(0)
				Expect(fmt.Sprintf(format, content...)).To(Equal("configuration previously completed, skipping configuration"))
			})
		})

		Context("when config file is provided", func() {
			var configFile *os.File

			BeforeEach(func() {
				var err error
				configContent := `
ldap-server-url: ldap://ldap.example.com:389
ldap-username: username
ldap-password: password
ldap-user-search-base: ou=users,dc=mycompany,dc=com
ldap-user-search-filter: cn={0}
ldap-group-search-base: ou=groups,dc=mycompany,dc=com
ldap-group-search-filter: member={0}
ldap-referrals: follow
ldap-server-ssl-cert: |
  -----BEGIN CERTIFICATE-----
  certificate data
  ----- END CERTIFICATE -----
ldap-rbac-admin-group: admin
ldap-email-attribute: mail
decryption-passphrase: some-passphrase
`
				configFile, err = ioutil.TempFile("", "")
				Expect(err).NotTo(HaveOccurred())

				_, err = configFile.WriteString(configContent)
				Expect(err).NotTo(HaveOccurred())
			})

			It("reads configuration from config file", func() {
				service := &fakes.ConfigureAuthenticationService{}
				eaOutputs := []api.EnsureAvailabilityOutput{
					{Status: api.EnsureAvailabilityStatusUnstarted},
					{Status: api.EnsureAvailabilityStatusPending},
					{Status: api.EnsureAvailabilityStatusPending},
					{Status: api.EnsureAvailabilityStatusComplete},
				}

				service.EnsureAvailabilityStub = func(api.EnsureAvailabilityInput) (api.EnsureAvailabilityOutput, error) {
					return eaOutputs[service.EnsureAvailabilityCallCount()-1], nil
				}

				logger := &fakes.Logger{}

				command := commands.NewConfigureLDAPAuthentication(service, logger)
				err := command.Execute([]string{
					"--config", configFile.Name(),
				})
				Expect(err).NotTo(HaveOccurred())

				Expect(service.SetupArgsForCall(0)).To(Equal(api.SetupInput{
					IdentityProvider:                 "ldap",
					DecryptionPassphrase:             "some-passphrase",
					DecryptionPassphraseConfirmation: "some-passphrase",
					EULAAccepted:                     "true",
					LDAPSettings: api.LDAPSettings{
						ServerURL:          "ldap://ldap.example.com:389",
						EmailAttribute:     "mail",
						GroupSearchBase:    "ou=groups,dc=mycompany,dc=com",
						GroupSearchFilter:  "member={0}",
						UserSearchBase:     "ou=users,dc=mycompany,dc=com",
						UserSearchFilter:   "cn={0}",
						Username:           "username",
						Password:           "password",
						Referrals:          "follow",
						RBACAdminGroupName: "admin",
						ServerSSLCert:      "-----BEGIN CERTIFICATE-----\ncertificate data\n----- END CERTIFICATE -----\n",
					},
				}))

				Expect(service.EnsureAvailabilityCallCount()).To(Equal(4))

				format, content := logger.PrintfArgsForCall(0)
				Expect(fmt.Sprintf(format, content...)).To(Equal("configuring LDAP authentication..."))

				format, content = logger.PrintfArgsForCall(1)
				Expect(fmt.Sprintf(format, content...)).To(Equal("waiting for configuration to complete..."))

				format, content = logger.PrintfArgsForCall(2)
				Expect(fmt.Sprintf(format, content...)).To(Equal("configuration complete"))
			})

			It("is overridden by commandline flags", func() {
				service := &fakes.ConfigureAuthenticationService{}
				eaOutputs := []api.EnsureAvailabilityOutput{
					{Status: api.EnsureAvailabilityStatusUnstarted},
					{Status: api.EnsureAvailabilityStatusPending},
					{Status: api.EnsureAvailabilityStatusPending},
					{Status: api.EnsureAvailabilityStatusComplete},
				}

				service.EnsureAvailabilityStub = func(api.EnsureAvailabilityInput) (api.EnsureAvailabilityOutput, error) {
					return eaOutputs[service.EnsureAvailabilityCallCount()-1], nil
				}

				logger := &fakes.Logger{}

				command := commands.NewConfigureLDAPAuthentication(service, logger)
				err := command.Execute([]string{
					"--config", configFile.Name(),
					"--ldap-server-url", "ldap://ldap.example.com:389",
				})
				Expect(err).NotTo(HaveOccurred())

				Expect(service.SetupArgsForCall(0)).To(Equal(api.SetupInput{
					IdentityProvider:                 "ldap",
					DecryptionPassphrase:             "some-passphrase",
					DecryptionPassphraseConfirmation: "some-passphrase",
					EULAAccepted:                     "true",
					LDAPSettings: api.LDAPSettings{
						ServerURL:          "ldap://ldap.example.com:389",
						EmailAttribute:     "mail",
						GroupSearchBase:    "ou=groups,dc=mycompany,dc=com",
						GroupSearchFilter:  "member={0}",
						UserSearchBase:     "ou=users,dc=mycompany,dc=com",
						UserSearchFilter:   "cn={0}",
						Username:           "username",
						Password:           "password",
						Referrals:          "follow",
						RBACAdminGroupName: "admin",
						ServerSSLCert:      "-----BEGIN CERTIFICATE-----\ncertificate data\n----- END CERTIFICATE -----\n",
					},
				}))

				Expect(service.EnsureAvailabilityCallCount()).To(Equal(4))

				format, content := logger.PrintfArgsForCall(0)
				Expect(fmt.Sprintf(format, content...)).To(Equal("configuring LDAP authentication..."))

				format, content = logger.PrintfArgsForCall(1)
				Expect(fmt.Sprintf(format, content...)).To(Equal("waiting for configuration to complete..."))

				format, content = logger.PrintfArgsForCall(2)
				Expect(fmt.Sprintf(format, content...)).To(Equal("configuration complete"))
			})
		})

		Context("failure cases", func() {
			Context("when an unknown flag is provided", func() {
				It("returns an error", func() {
					command := commands.NewConfigureLDAPAuthentication(&fakes.ConfigureAuthenticationService{}, &fakes.Logger{})
					err := command.Execute([]string{"--banana"})
					Expect(err).To(MatchError("could not parse configure-ldap-authentication flags: flag provided but not defined: -banana"))
				})
			})

			Context("when config file cannot be opened", func() {
				It("returns an error", func() {
					command := commands.NewConfigureLDAPAuthentication(&fakes.ConfigureAuthenticationService{}, &fakes.Logger{})
					err := command.Execute([]string{"--config", "something"})
					Expect(err).To(MatchError("could not parse configure-ldap-authentication flags: could not load the config file: open something: no such file or directory"))

				})
			})

			Context("when the initial configuration status cannot be determined", func() {
				It("returns an error", func() {
					service := &fakes.ConfigureAuthenticationService{}
					service.EnsureAvailabilityReturns(api.EnsureAvailabilityOutput{}, errors.New("failed to fetch status"))

					command := commands.NewConfigureLDAPAuthentication(service, &fakes.Logger{})
					err := command.Execute([]string{
						"--decryption-passphrase", "some-passphrase",
						"--ldap-server-url", "ldap://ldap.example.com:389",
						"--ldap-username", "username",
						"--ldap-password", "password",
						"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
						"--ldap-user-search-filter", "cn={0}",
						"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
						"--ldap-group-search-filter", "member={0}",
						"--ldap-referrals", "follow",
						"--ldap-server-ssl-cert", "/path/to/certificate",
						"--ldap-rbac-admin-group", "admin",
						"--ldap-email-attribute", "mail",
					})
					Expect(err).To(MatchError("could not determine initial configuration status: failed to fetch status"))
				})
			})

			Context("when the initial configuration status is unknown", func() {
				It("returns an error", func() {
					service := &fakes.ConfigureAuthenticationService{}
					service.EnsureAvailabilityReturns(api.EnsureAvailabilityOutput{
						Status: api.EnsureAvailabilityStatusUnknown,
					}, nil)

					command := commands.NewConfigureLDAPAuthentication(service, &fakes.Logger{})
					err := command.Execute([]string{
						"--decryption-passphrase", "some-passphrase",
						"--ldap-server-url", "ldap://ldap.example.com:389",
						"--ldap-username", "username",
						"--ldap-password", "password",
						"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
						"--ldap-user-search-filter", "cn={0}",
						"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
						"--ldap-group-search-filter", "member={0}",
						"--ldap-referrals", "follow",
						"--ldap-server-ssl-cert", "/path/to/certificate",
						"--ldap-rbac-admin-group", "admin",
						"--ldap-email-attribute", "mail",
					})
					Expect(err).To(MatchError("could not determine initial configuration status: received unexpected status"))
				})
			})

			Context("when the setup service encounters an error", func() {
				It("returns an error", func() {
					service := &fakes.ConfigureAuthenticationService{}
					service.EnsureAvailabilityReturns(api.EnsureAvailabilityOutput{
						Status: api.EnsureAvailabilityStatusUnstarted,
					}, nil)

					service.SetupReturns(api.SetupOutput{}, errors.New("could not setup"))

					command := commands.NewConfigureLDAPAuthentication(service, &fakes.Logger{})
					err := command.Execute([]string{
						"--decryption-passphrase", "some-passphrase",
						"--ldap-server-url", "ldap://ldap.example.com:389",
						"--ldap-username", "username",
						"--ldap-password", "password",
						"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
						"--ldap-user-search-filter", "cn={0}",
						"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
						"--ldap-group-search-filter", "member={0}",
						"--ldap-referrals", "follow",
						"--ldap-server-ssl-cert", "/path/to/certificate",
						"--ldap-rbac-admin-group", "admin",
						"--ldap-email-attribute", "mail",
					})
					Expect(err).To(MatchError("could not configure authentication: could not setup"))
				})
			})

			Context("when the final configuration status cannot be determined", func() {
				It("returns an error", func() {
					service := &fakes.ConfigureAuthenticationService{}

					eaOutputs := []api.EnsureAvailabilityOutput{
						{Status: api.EnsureAvailabilityStatusUnstarted},
						{Status: api.EnsureAvailabilityStatusUnstarted},
						{Status: api.EnsureAvailabilityStatusUnstarted},
						{Status: api.EnsureAvailabilityStatusUnstarted},
					}

					eaErrors := []error{nil, nil, nil, errors.New("failed to fetch status")}

					service.EnsureAvailabilityStub = func(api.EnsureAvailabilityInput) (api.EnsureAvailabilityOutput, error) {
						return eaOutputs[service.EnsureAvailabilityCallCount()-1], eaErrors[service.EnsureAvailabilityCallCount()-1]
					}

					command := commands.NewConfigureLDAPAuthentication(service, &fakes.Logger{})
					err := command.Execute([]string{
						"--decryption-passphrase", "some-passphrase",
						"--ldap-server-url", "ldap://ldap.example.com:389",
						"--ldap-username", "username",
						"--ldap-password", "password",
						"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
						"--ldap-user-search-filter", "cn={0}",
						"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
						"--ldap-group-search-filter", "member={0}",
						"--ldap-referrals", "follow",
						"--ldap-server-ssl-cert", "/path/to/certificate",
						"--ldap-rbac-admin-group", "admin",
						"--ldap-email-attribute", "mail",
					})
					Expect(err).To(MatchError("could not determine final configuration status: failed to fetch status"))
				})
			})

			Context("when the --ldap-server-url field is not configured with others", func() {
				It("returns an error", func() {
					command := commands.NewConfigureLDAPAuthentication(nil, nil)
					err := command.Execute([]string{
						"--decryption-passphrase", "some-passphrase",
						"--ldap-username", "username",
						"--ldap-password", "password",
						"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
						"--ldap-user-search-filter", "cn={0}",
						"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
						"--ldap-group-search-filter", "member={0}",
						"--ldap-referrals", "follow",
						"--ldap-server-ssl-cert", "/path/to/certificate",
						"--ldap-rbac-admin-group", "admin",
						"--ldap-email-attribute", "mail",
					})
					Expect(err).To(HaveOccurred())

					Expect(err).To(MatchError("could not parse configure-ldap-authentication flags: missing required flag \"--ldap-server-url\""))
				})
			})

			Context("when the --ldap-username field is not configured with others", func() {
				It("returns an error", func() {
					command := commands.NewConfigureLDAPAuthentication(nil, nil)
					err := command.Execute([]string{
						"--decryption-passphrase", "some-passphrase",
						"--ldap-server-url", "ldap://ldap.example.com:389",
						"--ldap-password", "password",
						"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
						"--ldap-user-search-filter", "cn={0}",
						"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
						"--ldap-group-search-filter", "member={0}",
						"--ldap-referrals", "follow",
						"--ldap-server-ssl-cert", "/path/to/certificate",
						"--ldap-rbac-admin-group", "admin",
						"--ldap-email-attribute", "mail",
					})
					Expect(err).To(HaveOccurred())

					Expect(err).To(MatchError("could not parse configure-ldap-authentication flags: missing required flag \"--ldap-username\""))
				})
			})

			Context("when the --ldap-password field is not configured with others", func() {
				It("returns an error", func() {
					command := commands.NewConfigureLDAPAuthentication(nil, nil)
					err := command.Execute([]string{
						"--decryption-passphrase", "some-passphrase",
						"--ldap-server-url", "ldap://ldap.example.com:389",
						"--ldap-username", "username",
						"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
						"--ldap-user-search-filter", "cn={0}",
						"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
						"--ldap-group-search-filter", "member={0}",
						"--ldap-referrals", "follow",
						"--ldap-server-ssl-cert", "/path/to/certificate",
						"--ldap-rbac-admin-group", "admin",
						"--ldap-email-attribute", "mail",
					})
					Expect(err).To(HaveOccurred())

					Expect(err).To(MatchError("could not parse configure-ldap-authentication flags: missing required flag \"--ldap-password\""))
				})
			})

			Context("when the --ldap-user-search-base field is not configured with others", func() {
				It("returns an error", func() {
					command := commands.NewConfigureLDAPAuthentication(nil, nil)
					err := command.Execute([]string{
						"--decryption-passphrase", "some-passphrase",
						"--ldap-server-url", "ldap://ldap.example.com:389",
						"--ldap-username", "username",
						"--ldap-password", "password",
						"--ldap-user-search-filter", "cn={0}",
						"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
						"--ldap-group-search-filter", "member={0}",
						"--ldap-referrals", "follow",
						"--ldap-server-ssl-cert", "/path/to/certificate",
						"--ldap-rbac-admin-group", "admin",
						"--ldap-email-attribute", "mail",
					})
					Expect(err).To(HaveOccurred())

					Expect(err).To(MatchError("could not parse configure-ldap-authentication flags: missing required flag \"--ldap-user-search-base\""))
				})
			})

			Context("when the --ldap-rbac-admin-group field is not configured with others", func() {
				It("returns an error", func() {
					command := commands.NewConfigureLDAPAuthentication(nil, nil)
					err := command.Execute([]string{
						"--decryption-passphrase", "some-passphrase",
						"--ldap-server-url", "ldap://ldap.example.com:389",
						"--ldap-username", "username",
						"--ldap-password", "password",
						"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
						"--ldap-user-search-filter", "cn={0}",
						"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
						"--ldap-group-search-filter", "member={0}",
						"--ldap-referrals", "follow",
						"--ldap-server-ssl-cert", "/path/to/certificate",

						"--ldap-email-attribute", "mail",
					})
					Expect(err).To(HaveOccurred())

					Expect(err).To(MatchError("could not parse configure-ldap-authentication flags: missing required flag \"--ldap-rbac-admin-group\""))
				})
			})

			Context("when the --decryption-passphrase flag is missing", func() {
				It("returns an error", func() {
					command := commands.NewConfigureLDAPAuthentication(nil, nil)
					err := command.Execute([]string{
						"--ldap-server-url", "ldap://ldap.example.com:389",
						"--ldap-username", "username",
						"--ldap-password", "password",
						"--ldap-user-search-base", "ou=users,dc=mycompany,dc=com",
						"--ldap-user-search-filter", "cn={0}",
						"--ldap-group-search-base", "ou=groups,dc=mycompany,dc=com",
						"--ldap-group-search-filter", "member={0}",
						"--ldap-referrals", "follow",
						"--ldap-server-ssl-cert", "/path/to/certificate",
						"--ldap-rbac-admin-group", "admin",
						"--ldap-email-attribute", "mail",
					})
					Expect(err).To(MatchError("could not parse configure-ldap-authentication flags: missing required flag \"--decryption-passphrase\""))
				})
			})
		})
	})

	Describe("Usage", func() {
		It("returns usage information for the command", func() {
			command := commands.NewConfigureLDAPAuthentication(nil, nil)
			Expect(command.Usage()).To(Equal(jhanda.Usage{
				Description:      "This unauthenticated command helps setup the authentication mechanism for your Ops Manager with LDAP.",
				ShortDescription: "configures Ops Manager with LDAP authentication",
				Flags:            command.Options,
			}))
		})
	})
})
