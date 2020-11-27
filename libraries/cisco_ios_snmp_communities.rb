class CiscoIOSSnmpCommunities < CiscoIOSBase
  name 'cisco_ios_snmp_communities'

  desc '
    Cisco IOS SNMP Communities Resource
  '

  example <<-EXP
    describe cisco_ios_snmp_communities.where(name: 'private') do
      its('entries') { should be_empty }
    end
  EXP

  filter = FilterTable.create
  filter.add_accessor(:where)
        .add_accessor(:entries)
        .add(:access_list, field: :access_list)
        .add(:index, field: :index)
        .add(:name, field: :name)
        .add(:mode, field: :mode)
        .add(:security_name, field: :security_name)
        .add(:storage_type, field: :storage_type)

  filter.connect(self, :params)

  def initialize
    unless inspec.cisco_ios_snmp.enabled?
      raise Inspec::Exceptions::ResourceSkipped, 'SNMP is not enabled'
    end
  end

  def to_s
    'Cisco IOS SNMP Communities'
  end

  def params
    return nil unless inspec.cisco_ios_snmp.enabled?

    parse_snmp_communities(File.read('output/show_snmp_community'))
  end

  private

  def parse_snmp_communities(output)
    raw_communities = output.split("\n")

    communities = []
    raw_communities.each do |raw_community|
      communities.push(translate_raw_community(raw_community))
    end
    communities
  end

  def translate_raw_community(raw_community)
    community = {}

    split_raw_community(raw_community).each do |k, v|
      k = k.gsub('access-list', 'access_list')
           .gsub('Community name', 'name')
           .gsub('Community Index', 'index')
           .gsub('Community SecurityName', 'security_name')
           .gsub('storage-type', 'storage_type')

      v = v.gsub("read-only\t active", 'read-only')
           .gsub("nonvolatile\t active", 'nonvolatile')

      community[k.to_sym] = v
    end

    output = ''
    File.read("output/show_running_config") do |f|
      f.each_line do |line|
        if line =~ /#{community[:name]}/
          output += line.gsub(/\s+$/, '') + "\n"
        end
      end
    end
    community[:mode] = output =~ / RW( |$)/ ? 'RW' : 'RO'

    community
  end

  def split_raw_community(raw_community)
    # `access-list` is not on its own line and is not present if not set.
    # Example: `storage-type: nonvolatile\t active\taccess-list: 1`
    access_list = raw_community.slice!(/access-list:.*(\n)*/)

    parsed = raw_community.split("\n")
                          .reject(&:empty?)

    parsed.push(access_list) if access_list

    parsed.map { |x| x.split(':').map(&:strip) }
  end
end
