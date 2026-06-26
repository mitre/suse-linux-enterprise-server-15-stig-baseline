control 'SV-234815' do
  title 'The SUSE operating system must log SSH connection attempts and failures to the server.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Verify SSH is configured to verbosely log connection attempts and failed logon attempts to the SUSE operating system.

Check that the SSH daemon configuration verbosely logs connection attempts and failed logon attempts to the server with the following command:

> sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*loglevel'

The output message must contain the following text:

LogLevel VERBOSE

If the output message does not contain "VERBOSE", the LogLevel keyword is missing, or the line is commented out, this is a finding.)
  desc 'fix', 'Configure SSH to verbosely log connection attempts and failed logon attempts to the SUSE operating system.

Add or update the following line in the "/etc/ssh/sshd_config" file:

LogLevel VERBOSE

The SSH service will need to be restarted in order for the changes to take effect.'
  impact 0.5
  tag check_id: 'C-38003r951627_chk'
  tag severity: 'medium'
  tag gid: 'V-234815'
  tag rid: 'SV-234815r958406_rule'
  tag stig_id: 'SLES-15-010150'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-37966r618715_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  describe sshd_config do
    its('LogLevel') { should cmp 'VERBOSE' }
  end
end
