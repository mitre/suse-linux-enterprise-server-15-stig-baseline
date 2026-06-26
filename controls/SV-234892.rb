control 'SV-234892' do
  title 'The SUSE operating system must employ user passwords with a maximum lifetime of 60 days.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the SUSE operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the SUSE operating system passwords could be compromised.'
  desc 'check', %q(Verify that the SUSE operating system enforces a maximum user password age of 60 days or less.

Check that the SUSE operating system enforces 60 days or less as the maximum user password age with the following command:

> sudo awk -F: '$5 > 60 || $5 == "" {print $1 ":" $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to enforce a maximum password age of each [USER] account to 60 days. The command in the check text will give a list of users that need to be updated to be in compliance:

> sudo passwd -x 60 [USER]

The DOD requirement is 60 days.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-234892'
  tag rid: 'SV-234892r1038967_rule'
  tag stig_id: 'SLES-15-020230'
  tag fix_id: 'F-38043r986491_fix'
  tag cci: ['CCI-000199', 'CCI-004066']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  value = input('pass_max_days')
  setting = input_object('pass_max_days').name.upcase

  describe "/etc/login.defs does not have `#{setting}` configured" do
    let(:config) { login_defs.read_params[setting] }
    it "greater than #{value} day" do
      expect(config).to cmp <= value
    end
  end
end
