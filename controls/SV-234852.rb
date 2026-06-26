control 'SV-234852' do
  title 'The SUSE operating system tool zypper must have gpgcheck enabled.'
  desc 'Changes to any software components can have significant effects on the overall security of SLES 12. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or SLES 12 components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. SLES 12 should not have to verify the software again. This requirement does not mandate DOD certificates for this purpose; however, the certificate used to verify the software must be from an approved Certification Authority (CA).

For zypper on SUSE Linux Enterprise systems, GPG signature checking is enabled by default for all repositories, even if it is not explicitly set in /etc/zypp/zypp.conf or individual .repo files. The presence of the gpgcheck setting in repository files (like gpgcheck=1) or a global zypp.conf entry would override this default behavior if a user wanted to disable it (e.g., gpgcheck=0), but its absence simply means the default is in effect.'
  desc 'check', %q(Verify the SLES 12 zypper tool has gpgcheck enabled with the following command: 

     > grep -i '^gpgcheck' /etc/zypp/zypp.conf

If "gpgcheck" is set to "off", this is a finding.)
  desc 'fix', 'Configure the SLES 12 zypper tool to enable gpgcheck.

Add or modify the following line in the "/etc/zypp/zypp.conf" file or remove the line completely ensuring that the default zypper setting is enabled:

gpgcheck = on'
  impact 0.7
  tag check_id: 'C-38040r1190818_chk'
  tag severity: 'high'
  tag gid: 'V-234852'
  tag rid: 'SV-234852r1190820_rule'
  tag stig_id: 'SLES-15-010430'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-38003r1190819_fix'
  tag 'documentable'
  tag cci: ['CCI-001749', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-14']
  tag 'host'
  tag 'container'

  repo_def_files = command('ls /etc/yum.repos.d/*.repo').stdout.split("\n")

  if repo_def_files.empty?
    describe 'No repos found in /etc/yum.repos.d/*.repo' do
      skip 'No repos found in /etc/yum.repos.d/*.repo'
    end
  else
    # pull out all repo definitions from all files into one big hash
    repos = repo_def_files.map { |file| parse_config_file(file).params }.inject(&:merge)

    # check big hash for repos that fail the test condition
    failing_repos = repos.keys.reject { |repo_name| repos[repo_name]['gpgcheck'] == '1' }

    describe 'All repositories' do
      it 'should be configured to verify digital signatures' do
        expect(failing_repos).to be_empty, "Misconfigured repositories:\n\t- #{failing_repos.join("\n\t- ")}"
      end
    end
  end
end
