class CiscoIOSInterfaces < CiscoIOSBase
  name 'cisco_ios_interfaces'

  desc '
    Cisco IOS Interfaces Resource
  '

  example <<-EXP
    describe cisco_ios_interfaces.where(name: /Loopback/ ) do
      its('entries') { should_not be_empty }
    end
  EXP

  filter = FilterTable.create
  filter.add_accessor(:where)
        .add_accessor(:entries)
        .add(:authentication_key_chain, field: :authentication_key_chain)
        .add(:authentication_mode, field: :authentication_mode)
        .add(:cidr_mask, field: :cidr_mask)
        .add(:down?, field: :down?)
        .add(:ip_address, field: :ip_address)
        .add(:line_protocol_status, field: :line_protocol_status)
        .add(:line_protocol_up?, field: :line_protocol_up?)
        .add(:line_protocol_down?, field: :line_protocol_down?)
        .add(:mtu, field: :mtu)
        .add(:name, field: :name)
        .add(:proxy_arp_enabled?, field: :proxy_arp_enabled?)
        .add(:protocols, field: :protocols)
        .add(:rip_authentication_key_chain, field: :rip_authentication_key_chain)
        .add(:rip_authentication_mode, field: :rip_authentication_mode)
        .add(:status, field: :status)
        .add(:up?, field: :up?)
        .add(:ip_verify_source, field: :ip_verify_source)

  filter.connect(self, :params)

  def to_s
    'Cisco IOS Interfaces'
  end

  def params
    parse_lines(File.read('output/show_ip_interface').split("\n"))
  end

  private

  def parse_lines(lines)
    interfaces = []
    lines.each do |line|
      if line =~ /^\S/
        interfaces.push(parse_interface_line(line))
        other_info = add_other_info(interfaces[-1][:name])
        if !other_info.nil?
          interfaces[-1].merge!(other_info)
        end
      else
        interfaces[-1].merge!(parse_info_line(line))
      end
    end
    interfaces
  end

  def parse_interface_line(line)
    x = line.split(',').map { |y| y.split('is').map(&:strip) }
    {
      name: x[0][0],
      status: x[0][1],
      up?: x[0][1] == 'up',
      down?: x[0][1] == 'down',
      line_protocol_status: x[1][1],
      line_protocol_up?: x[1][1] == 'up',
      line_protocol_down?: x[1][1] == 'down'
    }
  end

  def parse_info_line(line)
    case line
    when /Internet address is/
      return {
        ip_address: line.split(/ is /)[-1].split('/')[0],
        cidr_mask: line.split(/ is /)[-1].split('/')[1]
      }
    when /IP verify source/
      return { ip_verify_source: line.split(/ source /)[-1] }
    when /MTU is/
      return { mtu: line.split(/ /)[-2] }
    when /Proxy ARP is/
      return { proxy_arp_enabled?: line.split(/ is /)[-1] == 'enabled' }
    end

    {}
  end

  def add_other_info(interface_name)
    info = {}
    protocols = []
    output = ''
    int_name = interface_name.gsub('/','_')
    filename = "output/show_run_interface_#{int_name}"
    if File.exist?(filename)
      output = File.read(filename)
    
      output.split("\n").each do |line|
        case line
        when /[^r]ip authentication key-chain/
          info[:authentication_key_chain] = line.split(/ /)[-1]
          protocols.push('eigrp')
        when /[^r]ip authentication mode/
          info[:authentication_mode] = line.split(/ /)[-1]
        when /[^r]ip ospf message-digest-key/
          protocols.push('ospf')
        when /ip rip authentication key-chain/
          info[:rip_authentication_key_chain] = line.split(/ /)[-1]
          protocols.push('ripv2')
        when /ip rip authentication mode/
          info[:rip_authentication_mode] = line.split(/ /)[-1]
        end
      end

      if !protocols.empty?
        info.merge(protocols: protocols)
      end
    end
  end
end
