control 'SV-234857' do
  title 'If Network Security Services (NSS) is being used by the SUSE operating system it must prohibit the use of cached authentications after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'If NSS is not used on the operating system, this is Not Applicable.

If NSS is used by the SUSE operating system, verify it prohibits the use of cached authentications after one day.

Check that cached authentications cannot be used after one day with the following command:

> sudo grep -i "memcache_timeout" /etc/sssd/sssd.conf

memcache_timeout = 86400

If "memcache_timeout" has a value greater than "86400", or is missing, this is a finding.'
  desc 'fix', 'Configure NSS, if used by the SUSE operating system, to prohibit the use of cached authentications after one day.

Add or change the following line in "/etc/sssd/sssd.conf" just below the line "[nss]":

memcache_timeout = 86400'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag gid: 'V-234857'
  tag rid: 'SV-234857r958828_rule'
  tag stig_id: 'SLES-15-010490'
  tag fix_id: 'F-38008r618841_fix'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
  tag 'host'

  sssd_config = parse_config_file('/etc/sssd/sssd.conf')

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  nss_timeout = sssd_config.params.dig('nss', 'memcache_timeout')

  describe 'SSSD [nss] memcache_timeout' do
    it "is set and does not exceed #{input('nss_memcache_timeout')} seconds (one day)" do
      expect(nss_timeout).not_to be_nil, 'memcache_timeout is not set under [nss] in /etc/sssd/sssd.conf'
      expect(nss_timeout.to_i).to be <= input('nss_memcache_timeout') unless nss_timeout.nil?
    end
  end
end
