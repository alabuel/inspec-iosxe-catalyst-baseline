class CiscoIOSSnmpCommunity < CiscoIOSBase
  name 'cisco_ios_snmp_community'

  desc '
    Cisco IOS SNMP Community Resource
  '

  example <<-EXP
    describe cisco_ios_snmp_community('private') do
      it { should_not exist }
    end
  EXP

  def initialize(community_name)
    @name = community_name
    @info = {}
    community = gather_info(community_name)
    @info[:exist?] = true unless community.nil?

    add_methods(community)
  end

  def to_s
    "Cisco IOS SNMP Community #{@name}"
  end

  def exist?
    @info[:exist?] == true
  end

  private

  def gather_info(community_name)
    communities = inspec.cisco_ios_snmp_communities.where(
                    name: community_name
                  ).entries

    if communities.length == 1
      return communities[0]
    elsif communities.length > 1
      raise Inspec::Exceptions::ResourceFailed,
            "Community `#{community_name}` does not have a unique name " \
            'Please use unique name or the `cisco_ios_communities` resource'
    end
  end

  def add_methods(community)
    community.to_h.each_pair do |k, v|
      define_singleton_method(k) { v }
    end
  end
end
