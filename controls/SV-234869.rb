control 'SV-234869' do
  title 'The SUSE operating system must implement multifactor authentication for access to privileged accounts via pluggable authentication modules (PAM).'
  desc 'Using an authentication device, such as a Common Access Card (CAC) or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification (PIV) card and the DOD CAC.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).'
  desc 'check', 'Verify the SUSE operating system implements multifactor authentication for remote access to privileged accounts via PAM.

Check that the "pam_pkcs11.so" option is configured in the "/etc/pam.d/common-auth" file with the following command:

> grep pam_pkcs11.so /etc/pam.d/common-auth

auth sufficient pam_pkcs11.so

If "pam_pkcs11.so" is not set in "/etc/pam.d/common-auth", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to implement multifactor authentication for remote access to privileged accounts via PAM.

Add or update "pam_pkcs11.so" in "/etc/pam.d/common-auth" to match the following line:

auth sufficient pam_pkcs11.so'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag gid: 'V-234869'
  tag rid: 'SV-234869r1009617_rule'
  tag stig_id: 'SLES-15-020030'
  tag fix_id: 'F-38020r618877_fix'
  tag cci: ['CCI-000187', 'CCI-000765', 'CCI-000766', 'CCI-004046', 'CCI-001953', 'CCI-001954', 'CCI-004047', 'CCI-000767', 'CCI-000768', 'CCI-001948']
  tag nist: ['IA-5 (2) (c)', 'IA-5 (2) (a) (2)', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (6) (a)', 'IA-2 (12)', 'IA-2 (6) (b)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (11)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternate_mfa_method') == ''
    describe file('/etc/sssd/sssd.conf') do
      it { should exist }
      its('content') { should match(/^\s*\[certmap.*\]\s*$/) }
    end
  else
    impact 0.0
    describe 'N/A' do
      skip 'The system is using an approved alternative MFA method; this control is Not Applicable.'
    end
  end
end
