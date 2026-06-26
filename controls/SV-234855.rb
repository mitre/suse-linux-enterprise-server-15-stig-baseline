control 'SV-234855' do
  title 'The SUSE operating system must implement certificate status checking for multifactor authentication.'
  desc 'Using an authentication device, such as a common access card (CAC) or token separate from the information system, ensures credentials stored on the authentication device will not be affected if the information system is compromised.

Multifactor solutions that require devices separate from information systems to gain access include hardware tokens providing time-based or challenge-response authenticators, and smart cards such as the U.S. Government Personal Identity Verification (PIV) card and the DOD CAC.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components with device-specific functions, or for organizational users (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).'
  desc 'check', %q(Verify the SUSE operating system implements certificate status checking for multifactor authentication.

Check that certificate status checking for multifactor authentication is implemented with the following command:

> grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module coolkey {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy

cert_policy = ca,ocsp_on,signature,crl_auto;

If "cert_policy" is not set to include "ocsp_on", this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to certificate status checking for PKI authentication.

Modify all of the cert_policy lines in "/etc/pam_pkcs11/pam_pkcs11.conf" to include "ocsp_on".

Note: OCSP allows sending request for certificate status information. Additional certificate validation polices are permitted.

Additional information on the configuration of multifactor authentication on the SUSE operating system can be found at https://www.suse.com/communities/blog/configuring-smart-card-authentication-suse-linux-enterprise/.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000377-GPOS-00162', 'SRG-OS-000376-GPOS-00161']
  tag gid: 'V-234855'
  tag rid: 'SV-234855r1155789_rule'
  tag stig_id: 'SLES-15-010470'
  tag fix_id: 'F-38006r618835_fix'
  tag cci: ['CCI-001948', 'CCI-001954', 'CCI-004046', 'CCI-001953']
  tag nist: ['IA-2 (11)', 'IA-2 (12)', 'IA-2 (6) (a)']
  tag 'host'

  only_if('This requirement is Not Applicable inside the container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternate_mfa_method').to_s.empty?
    sssd_conf_files = input('sssd_conf_files')
    sssd_conf_contents = ini({ command: "cat #{input('sssd_conf_files').join(' ')}" })
    sssd_certificate_verification = input('sssd_certificate_verification')

    describe 'SSSD' do
      it 'should be installed and enabled' do
        expect(service('sssd')).to be_installed.and be_enabled
        expect(sssd_conf_contents.params).to_not be_empty, "SSSD configuration files not found or have no content; files checked:\n\t- #{sssd_conf_files.join("\n\t- ")}"
      end
      if sssd_conf_contents.params.nil?
        it "should configure certificate_verification to be '#{sssd_certificate_verification}'" do
          expect(sssd_conf_contents.sssd.certificate_verification).to eq(sssd_certificate_verification)
        end
      end
    end
  else
    impact 0.0
    describe 'N/A' do
      skip 'The system is using an approved alternative MFA method; this control is Not Applicable.'
    end
  end
end
