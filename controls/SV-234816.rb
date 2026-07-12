control 'SV-234816' do
  title 'The SUSE operating system must implement DOD-approved encryption to protect the confidentiality of SSH remote connections.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

The system will attempt to use the first cipher presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest cipher available to secure the SSH connection.'
  desc 'check', %q(Verify the SUSE operating system implements DOD-approved encryption to protect the confidentiality of SSH remote connections.

Check the SSH daemon configuration for allowed ciphers with the following command:

> sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*ciphers'

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, or the "Ciphers" keyword is missing, this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration (/etc/ssh/sshd_config) and remove any ciphers not starting with "aes" and remove any ciphers ending with "cbc". If necessary, add a "Ciphers" line:

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

Restart the SSH daemon:

> sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-38004r951629_chk'
  tag severity: 'medium'
  tag gid: 'V-234816'
  tag rid: 'SV-234816r958408_rule'
  tag stig_id: 'SLES-15-010160'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-37967r618718_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe sshd_config do
    its('Ciphers') { should cmp 'aes256-ctr,aes192-ctr,aes128-ctr' }
  end
end
