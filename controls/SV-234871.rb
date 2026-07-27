control 'SV-234871' do
  title 'The SUSE operating system must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity after password expiration.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

The SUSE operating system needs to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', %q(Verify the SUSE operating system disables account identifiers after 35 days of inactivity since the password expiration.

Check the account inactivity value by performing the following command:

> sudo grep -i '^inactive' /etc/default/useradd

INACTIVE=35

If no output is produced, or if "INACTIVE" is not set to a value greater than "0" and less than or equal to "35", this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to disable account identifiers after 35 days of inactivity since the password expiration.

Run the following command to change the configuration for "useradd" to disable the account identifier after 35 days:

> sudo useradd -D -f 35

DOD recommendation is 35 days, but a lower value greater than "0" is acceptable.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag gid: 'V-234871'
  tag rid: 'SV-234871r1009619_rule'
  tag stig_id: 'SLES-15-020050'
  tag fix_id: 'F-38022r928530_fix'
  tag cci: ['CCI-000795', 'CCI-003627', 'CCI-003628']
  tag nist: ['IA-4 e', 'AC-2 (3) (a)', 'AC-2 (3) (b)']
  tag 'host'
  tag 'container'

  days_of_inactivity = input('days_of_inactivity')

  describe 'Useradd configuration' do
    useradd_config = parse_config_file('/etc/default/useradd')

    context 'when INACTIVE is set' do
      it 'should exist' do
        expect(useradd_config.params).to include('INACTIVE')
      end

      it 'should not be nil' do
        expect(useradd_config.params['INACTIVE']).not_to be_nil
      end

      it 'should have INACTIVE greater than or equal to 0' do
        expect(useradd_config.params['INACTIVE'].to_i).to be >= 0
      end

      it 'should have INACTIVE less than or equal to days_of_inactivity' do
        expect(useradd_config.params['INACTIVE'].to_i).to be <= days_of_inactivity
      end

      it 'should not have INACTIVE equal to -1' do
        expect(useradd_config.params['INACTIVE']).not_to eq '-1'
      end
    end
  end
end
