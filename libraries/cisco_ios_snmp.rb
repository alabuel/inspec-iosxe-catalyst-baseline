class CiscoIOSSnmp < CiscoIOSBase
  name 'cisco_ios_snmp'

  example <<-EXP
    describe cisco_ios_snmp do
      it { should be_enabled }
    end

    describe cisco_ios_snmp do
      its('hosts') { should_not be_empty }
    end
  EXP

  def to_s
    'Cisco IOS SNMP'
  end

  def enabled?
    @enabled ||= File.read('output/show_snmp') != '%SNMP agent not enabled'
  end

  def chassis
    return nil unless enabled?

    @chassis ||= File.read('output/show_snmp_chassis')
  end

  def hosts
    return nil unless enabled?

    @hosts ||= parse_snmp_hosts(File.read('output/show_snmp_host'))
  end

  def lines
    return nil unless enabled?

    @lines ||= File.read('output/show_snmp').split("\n")
  end

  private

  def parse_snmp_hosts(stdout)
    hosts = []
    stdout.split("\n\n").each do |data|
      data = data.split("\n")
                 .map { |x| x.split("\t") }
                 .flatten
      hosts.push(translate_host_data(data))
    end

    hosts
  end

  def translate_host_data(data)
    host = {}
    data.each do |d|
      key, value = d.split(':').map(&:strip)
      key = key.gsub('Notification host', 'host')
               .gsub('udp-port', 'port')
               .gsub('security model', 'security_model')
      host[key.to_sym] = value
    end

    OpenStruct.new(host)
  end
end
