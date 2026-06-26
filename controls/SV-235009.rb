control 'SV-235009' do
  title 'The SUSE operating system SSH daemon private host key files must have mode 0640 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the
host could be impersonated.'
  desc 'check', %q(Verify the SUSE operating system SSH daemon private host key files have mode "0640" or less permissive.

The following command will find all SSH private key files on the system:

     > sudo find / -name '*ssh_host*key' -exec ls -lL {} \;

Check the mode of the private host key files under "/etc/ssh" file with the following command:

     > find /etc/ssh -name 'ssh_host*key' -exec stat -c "%a %n" {} \;

     640 /etc/ssh/ssh_host_rsa_key
     640 /etc/ssh/ssh_host_dsa_key
     640 /etc/ssh/ssh_host_ecdsa_key
     640 /etc/ssh/ssh_host_ed25519_key

If any file has a mode more permissive than "0640", this is a finding.)
  desc 'fix', 'Configure the mode of the SUSE operating system SSH daemon private host key files under "/etc/ssh" to "0640" with the following command:

     > sudo chmod 0640 /etc/ssh/ssh_host*key'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-235009'
  tag rid: 'SV-235009r991589_rule'
  tag stig_id: 'SLES-15-040250'
  tag fix_id: 'F-38160r880957_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  ssh_host_key_dirs = input('ssh_host_key_dirs').join(' ')
  priv_keys = command("find #{ssh_host_key_dirs} -xdev -name '*.pem'").stdout.split("\n")
  mode = input('ssh_private_key_mode')
  failing_keys = priv_keys.select { |key| file(key).more_permissive_than?(mode) }

  describe 'All SSH private keys on the filesystem' do
    it "should be less permissive than #{mode}" do
      expect(failing_keys).to be_empty, "Failing keyfiles:\n\t- #{failing_keys.join("\n\t- ")}"
    end
  end
end
