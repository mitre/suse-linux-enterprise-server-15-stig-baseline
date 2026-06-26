control 'SV-234849' do
  title 'The SUSE operating system clock must, for networked systems, be synchronized to an authoritative DOD time source at least every 24 hours.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'The SUSE operating system clock must be configured to synchronize to an authoritative DOD time source when the time difference is greater than one second. 

Check that the SUSE operating system clock must be configured to synchronize to an authoritative DOD time source when the time difference is greater than one second with the following command:

> sudo grep maxpoll /etc/chrony.conf

server 0.us.pool.ntp.mil maxpoll 16

If nothing is returned, "maxpoll" is greater than "16", or is commented out, this is a finding.

Verify the "chrony.conf" file is configured to an authoritative DOD time source by running the following command:

> sudo grep -i server /etc/chrony.conf
server 0.us.pool.ntp.mil 

If the parameter "server" is not set, is not set to an authoritative DOD time source, or is commented out, this is a finding.'
  desc 'fix', 'The SUSE operating system clock must be configured to synchronize to an authoritative DOD time source when the time difference is greater than one second. 

To configure the system clock to synchronize to an authoritative DOD time source at least every 24 hours, edit the file "/etc/chrony.conf". Add or correct the following lines by replacing "[time_source]" with an authoritative DOD time source:

server [time_source] maxpoll 16'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144', 'SRG-OS-000359-GPOS-00146']
  tag gid: 'V-234849'
  tag rid: 'SV-234849r1038944_rule'
  tag stig_id: 'SLES-15-010400'
  tag fix_id: 'F-38000r986467_fix'
  tag cci: ['CCI-001891', 'CCI-001890', 'CCI-002046', 'CCI-004923', 'CCI-004926']
  tag nist: ['AU-8 (1) (a)', 'AU-8 b', 'AU-8 (1) (b)', 'SC-45 (1) (a)', 'SC-45 (1) (b)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  # Get inputs
  authoritative_timeservers = [input('authoritative_timeservers')].flatten
  match_all_authoritative_timeservers_enabled = input('match_all_authoritative_timeservers_enabled')

  # Get the system server values (might be part of a pool)
  # Converts to array if only one value present
  time_sources = []
  time_sources = [chrony_conf.server].flatten if chrony_conf.server
  time_sources += [chrony_conf.pool].flatten if chrony_conf.pool

  # Get and map maxpoll values to an array
  unless time_sources.nil?
    # Map max poll values only
    max_poll_values = time_sources.map { |val|
      val.match?(/.*maxpoll.*/) ? val.gsub(/.*maxpoll\s+(\d+)(\s+.*|$)/, '\1').to_i : 10
    }

    # Map server values only
    server_values = time_sources.map { |val|
      val.split.first
    }
  end

  # Verify the "chrony.conf" file is configured to a time source by running the following command:
  describe.one do
    describe chrony_conf do
      its('server') { should_not be_nil }
    end
    describe chrony_conf do
      its('pool') { should_not be_nil }
    end
  end

  unless time_sources.nil?
    # Verify the chrony.conf file is configured to at least one authoritative DoD time source
    # Check for valid maxpoll value <17
    describe 'chrony.conf' do
      # authoritative_timeservers_exact specifies whether to verify all inputted timeservers or just one
      if match_all_authoritative_timeservers_enabled
        it 'should include all specified valid timeservers' do
          expect(authoritative_timeservers.all? { |input|
                   server_values.include?(input) && max_poll_values[server_values.index(input)] <= 16
                 }).to be true
        end
      else
        it 'should include at least one valid timeserver' do
          expect(authoritative_timeservers.any? { |input|
            server_values.include?(input) && max_poll_values[server_values.index(input)] <= 16
          }).to be true
        end
      end
    end
  end
end
