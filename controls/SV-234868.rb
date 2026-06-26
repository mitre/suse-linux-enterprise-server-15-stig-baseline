control 'SV-234868' do
  title 'The SUSE operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
  desc 'SUSE operating system management includes the ability to control the number of users and user sessions that utilize a SUSE operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to Denial-of-Service (DoS) attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.'
  desc 'check', 'Verify the SUSE operating system limits the number of concurrent sessions to 10 for all accounts and/or account types by running the following command:

> grep "maxlogins" /etc/security/limits.conf

The result must contain the following line:

* hard maxlogins 10

If the "maxlogins" item is missing, the line does not begin with a star symbol, or the value is not set to "10" or less, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to limit the number of concurrent sessions to "10" or less for all accounts and/or account types.

Add the following line to the file "/etc/security/limits.conf":

* hard maxlogins 10'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag gid: 'V-234868'
  tag rid: 'SV-234868r958398_rule'
  tag stig_id: 'SLES-15-020020'
  tag fix_id: 'F-38019r618874_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  setting = 'maxlogins'
  expected_value = input('concurrent_sessions_permitted')

  limits_files = command('ls /etc/security/limits.d/*.conf').stdout.strip.split
  limits_files.append('/etc/security/limits.conf')

  # make sure that at least one limits.conf file has the correct setting
  globally_set = limits_files.any? { |lf| !limits_conf(lf).read_params['*'].nil? && limits_conf(lf).read_params['*'].include?(['hard', setting.to_s, expected_value.to_s]) }

  # make sure that no limits.conf file has a value that contradicts the global set
  failing_files = limits_files.select { |lf|
    limits_conf(lf).read_params.values.flatten(1).any? { |l|
      l[1].eql?(setting) && l[2].to_i > expected_value
    }
  }
  describe 'Limits files' do
    it "should limit concurrent sessions to #{expected_value} by default" do
      expect(globally_set).to eq(true), "No global ('*') setting for concurrent sessions found"
    end
    it 'should not have any conflicting settings' do
      expect(failing_files).to be_empty, "Files with incorrect '#{setting}' settings:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
