control 'SV-234878' do
  title 'The SUSE operating system must require reauthentication when using the "sudo" command.'
  desc %q(Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the organization requires the user to re-authenticate when using the "sudo" command.

If the value is set to an integer less than 0, the user's time stamp will not expire and the user will not have to reauthenticate for privileged actions until the user's session is terminated.)
  desc 'check', %q(Verify the operating system requires re-authentication when using the "sudo" command to elevate privileges.

> sudo grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d
/etc/sudoers:Defaults timestamp_timeout=0

If conflicting results are returned, this is a finding.

If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding.)
  desc 'fix', 'Configure the "sudo" command to require reauthentication.
Edit the /etc/sudoers file:

> sudo visudo

Add or modify the following line:

Defaults timestamp_timeout=[value]

Note: The "[value]" must be a number that is greater than or equal to "0".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag gid: 'V-234878'
  tag rid: 'SV-234878r1050789_rule'
  tag stig_id: 'SLES-15-020102'
  tag fix_id: 'F-38029r986476_fix'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This requirement is Not Applicable in a container with no sudo installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || command('sudo').exist?
  }

  setting = 'timestamp_timeout'
  setting_value = sudoers(input('sudoers_config_files')).settings.Defaults[setting]

  describe 'Sudoers configuration' do
    it "should should set #{setting} to a non-negative number, exactly once" do
      expect(setting_value).to_not be_nil, "#{setting} not found inside sudoers config file(s)"
      expect(setting_value.count).to eq(1), "#{setting} set #{setting_value.count} times inside sudoers config file(s)"
      expect(setting_value.first.to_i).to be >= 0
    end
  end
end
