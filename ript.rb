# -*- coding: utf-8 -*-
# Copyright 2010 Dominik Elsbroek. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
# conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
# of conditions and the following disclaimer in the documentation and/or other materials
# provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY Dominik Elsbroek ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Dominik Elsbroek OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those of the
# authors and should not be interpreted as representing official policies, either expressed
# or implied, of Dominik Elsbroek. 

require "json"

class Iptables


  def configure_system
    # we dont need timestamps in tcp
    yield "echo 0 > /proc/sys/net/ipv4/tcp_timestamps"
    # we ignore broadcasts
    yield "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
    # we want reverse path filtering
    yield "echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter"
    # we ignore icmp bogus error responses
    yield "echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses"
    # we do not ignore all icmp messages
    yield "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all"
    # we dont accept source routes
    yield "echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route"
    # we dont accept redirects
    yield "echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects"
    # and we log martians
    yield "echo 1 > /proc/sys/net/ipv4/conf/all/log_martians"
    # default on windows is 128, linux is 64 and cisco routers have 255
#    yield "echo 255 > /proc/sys/net/ipv4/ip_default_ttl"
    # since manual page says default is to disable, lets to this
    yield "echo 0 > /proc/sys/net/ipv4/tcp_ecn"
    # we disable ip forwarding
    yield "echo 0 > /proc/sys/net/ipv4/ip_forward"
    # we will never send any redirects
    yield "echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects "
  end
  
  #
  def initialize cfg
    cfg ||= "./ript.json"
    @f4 = []
    @f6 = []
    # load config file
    raise "configuration file must be readable" unless File.exist? cfg and File.file? cfg and File.readable? cfg
    raise "could not load configuration file" unless (@fw = JSON.parse(File.read(cfg)))

    # we need to have a list of all devices. we will get this list while going through the ip versions
    @list_of_devices = []


    # read and set basic settings
    log_level = @fw['log_level']
    max_tcp_in_per_second = @fw['max_tcp_in_per_second']
    max_udp_in_per_second  = @fw['max_udp_in_per_second']
    max_icmp_in_per_second = @fw['max_icmp_in_per_second']
    max_tcp_out_per_second = @fw['max_tcp_out_per_second']
    max_udp_out_per_second  = @fw['max_udp_out_per_second']
    max_icmp_out_per_second = @fw['max_icmp_out_per_second']
    
    @default_log_syn_in = if @fw.has_key?('log_syn_in') && @fw['log_syn_in'].eql?("yes") then true else false end
    @default_log_syn_out = if @fw.has_key?('log_syn_out') && @fw['log_syn_out'].eql?("yes") then true else false end
    @default_log_established = if @fw.has_key?('log_established') && @fw['log_established'].eql?("yes") then true else false end
    @default_log_drop = if @fw.has_key?('log_drop') && @fw['log_drop'].eql?("yes") then true else false end
    @default_log_rejected = if @fw.has_key?('log_rejected') && @fw['log_rejected'].eql?("yes") then true else false end
    @default_log_invalid = if @fw.has_key?('log_invalid') && @fw['log_invalid'].eql?("yes") then true else false end
    @default_log_icmp_in = if @fw.has_key?('log_icmp_in') && @fw['log_icmp_in'].eql?("yes") then true else false end
    @default_log_icmp_out = if @fw.has_key?('log_icmp_out') && @fw['log_icmp_out'].eql?("yes") then true else false end


    @default_log_level = unless log_level then "5" else log_level end
    @default_max_tcp_in_per_second = unless max_tcp_in_per_second then "10" else max_tcp_in_per_second end
    @default_max_tcp_out_per_second = unless max_tcp_out_per_second then "100" else max_tcp_out_per_second end
    @default_max_udp_in_per_second = unless max_udp_in_per_second then "10" else max_udp_in_per_second end
    @default_max_udp_out_per_second = unless max_udp_out_per_second then "100" else max_udp_out_per_second end
    @default_max_icmp_in_per_second = unless max_icmp_in_per_second then "10" else max_icmp_in_per_second end
    @default_max_icmp_out_per_second = unless max_icmp_out_per_second then "10" else max_icmp_out_per_second end
    
    @f4_bin = @fw['iptables_bin']
    @f6_bin = @fw['ip6tables_bin']
    
    # add the initial rules
    @f4.concat initialize_rules
    @f6.concat initialize_rules
    @f4.concat create_logging_rules
    @f6.concat create_logging_rules
    
    # create rules for each ip version
    create_rules_for "ipv4" do |rule| 
      @f4 << rule
    end
    create_rules_for "ipv6" do |rule| 
      @f6 << rule
    end

    # no RH0 allowed!
    @f6 << "-A INPUT -m rt --rt-type 0 -j DROP"
    @f6 << "-A OUTPUT -m rt --rt-type 0 -j DROP"
    @f6 << "-A FORWARD -m rt --rt-type 0 -j DROP"


    # allow localhost communication if desired
    @list_of_devices.uniq!
    if @fw['allow_localhost_communication'].eql?("yes")
      @f4 << "-A INPUT -i lo -j ACCEPT"
      @f6 << "-A INPUT -i lo -j ACCEPT"
      @f4 << "-A OUTPUT -o lo -j ACCEPT"
      @f6 << "-A OUTPUT -o lo -j ACCEPT"  
    end
    create_deny_rules "ipv4"
    create_deny_rules "ipv6"
  end

  #
  def create_deny_rules ipv, iface = nil, iface_settings = nil
    if iface 
      cur_iface = @fw[ipv][iface]
    else
      cur_iface = @fw
    end
    my_rules_arr = if ipv.eql? "ipv4" then
                     @f4
                   else
                     @f6
                   end
    iface_in = if iface then
                 "-i #{iface}"
               else
                 ""
               end
    iface_out = if iface then
                 "-o #{iface}"
               else
                 ""
               end
    deny_with = if cur_iface.has_key?("deny_with") then
                  cur_iface["deny_with"].upcase
                else
                  @fw["deny_with"].upcase
                end
    reject_with = if cur_iface.has_key?("reject_with") then
                    " --reject_with " <<  cur_iface["reject_with"].upcase
                  else
                    if cur_iface.has_key?("reject_with") then
                      "--reject-with " << cur_iface["reject_with"]
                    else
                      ""
                    end
                  end
    # set DROP or REJECT rules with corresponding logging rules if given
    if deny_with.upcase.eql? "DROP"
      if nil == iface_settings and @default_log_drop
        my_rules_arr << "-A OUTPUT #{iface_out} -j #{@@LOGGING_DROPPED}"
        my_rules_arr << "-A INPUT #{iface_in} -j #{@@LOGGING_DROPPED}"
        return
      end
      if iface_settings
        my_rules_arr << "-A OUTPUT #{iface_out} -j #{iface_settings[:log_drop]}"
        my_rules_arr << "-A INPUT #{iface_in} -j #{iface_settings[:log_drop]}"
        return
      end
      my_rules_arr << "-A OUTPUT #{iface_out} -j DROP"
      my_rules_arr << "-A INPUT #{iface_in} -j DROP"
      return
    end
    if deny_with.eql? "REJECT"
      if nil == iface_settings and @default_log_rejected
        my_rules_arr << "-A OUTPUT #{iface_out} -j #{@@LOGGING_REJECTED} #{reject_with}"
        my_rules_arr << "-A INPUT #{iface_in} -j #{@@LOGGING_REJECTED} #{reject_with}"
        return
      end
      if iface_settings
        my_rules_arr << "-A OUTPUT #{iface_out} -j #{iface_settings[:log_reject]} #{reject_with}"
        my_rules_arr << "-A INPUT #{iface_in} -j #{iface_settings[:log_reject]} #{reject_with}"
        return
      end
      my_rules_arr << "-A OUTPUT #{iface_out} -j REJECT"
      my_rules_arr << "-A INPUT #{iface_in} -j REJECT"
      return # not necassary
    end
  end

  #
  def create_rules_for ipv
    @fw[ipv].each do |interface|
      iface = interface[0]
      @list_of_devices << iface
      cur_rule = "#{ipv}-#{iface}"
      cur_iface = @fw[ipv][iface]
      yield "-N #{cur_rule}"
      yield "-F #{cur_rule}"
=begin
      for each value the user is able to configure in the config file
      we check if this value is configured in the interface section.
      if not we take the value from the global configuration which can be either
      user defined or program default.
=end
      iface_settings = Hash.new
      iface_settings[:max_tcp_in_per_second] = if cur_iface.has_key?("max_tcp_in_per_second") then 
                                                 cur_iface["max_tcp_in_per_second"]
                                               else
                                                 @default_max_tcp_in_per_second
                                               end
      iface_settings[:max_udp_in_per_second]  = if cur_iface.has_key?("max_udp_in_per_second") then 
                                                  cur_iface["max_udp_in_per_second"]
                                                else
                                                  @default_max_udp_in_per_second
                                                end
      iface_settings[:max_icmp_in_per_second] = if cur_iface.has_key?("max_icmp_out_per_second") then
                                                  cur_iface["max_icmp_out_per_second"]
                                                else
                                                  @default_max_icmp_in_per_second
                                                end
      iface_settings[:max_tcp_out_per_second] = if cur_iface.has_key?("max_tcp_out_per_second") then 
                                                  cur_iface["max_tcp_out_per_second"]
                                                else
                                                  @default_max_tcp_in_per_second
                                                end
      iface_settings[:max_udp_out_per_second]  = if cur_iface.has_key?("max_udp_out_per_second") then 
                                                   cur_iface["max_udp_out_per_second"]
                                                 else
                                                   @default_max_udp_in_per_second
                                                 end
      iface_settings[:max_icmp_out_per_second] = if cur_iface.has_key?("max_icmp_out_per_second") then
                                                   cur_iface["max_icmp_out_per_second"]
                                                 else
                                                   @default_max_icmp_in_per_second
                                                 end
      
      iface_settings[:log_icmp_in] = unless cur_iface.has_key?("log_icmp_in") then
                                       if @default_log_icmp_in then
                                         @@LOGGING_ICMP_IN
                                       else
                                         "ACCEPT"
                                       end
                                     else 
                                       if cur_iface["log_icmp_in"].eql?("yes") then
                                         @@LOGGING_ICMP_IN
                                       else
                                         "ACCEPT"
                                       end
                                     end
      iface_settings[:log_icmp_out] = unless cur_iface.has_key?("log_icmp_out") then
                                        if @default_log_icmp_out then
                                          @@LOGGING_ICMP_OUT
                                        else
                                          "ACCEPT"
                                        end
                                      else 
                                        if cur_iface["log_icmp_out"].eql?("yes") then
                                          @@LOGGING_ICMP_OUT
                                        else
                                          "ACCEPT"
                                        end
                                      end
      iface_settings[:log_syn_in] = unless cur_iface.has_key?("log_syn_in") then
                                      if @default_log_syn_in then
                                        @@LOGGING_ACCEPTED_SYN_IN
                                      else
                                        "ACCEPT"
                                      end
                                    else
                                      if cur_iface["log_syn_in"].eql?("yes") then
                                        @@LOGGING_ACCEPTED_SYN_IN
                                      else
                                        "ACCEPT"
                                      end
                                    end
      
      iface_settings[:log_syn_out] = unless cur_iface.has_key?("log_syn_out") then
                                       if @default_log_syn_out then
                                         @@LOGGING_ACCEPTED_SYN_OUT        
                                       else
                                         "ACCEPT"
                                       end
                                     else
                                       if cur_iface["log_syn_out"].eql?("yes") then
                                         @@LOGGING_ACCEPTED_SYN_OUT        
                                       else
                                         "ACCEPT"
                                       end
                                     end
      iface_settings[:log_established] = unless cur_iface.has_key?("log_established") then
                                           if @default_log_established then
                                             @@LOGGING_ESTABLISHED
                                           else
                                             "ACCEPT"
                                           end
                                         else
                                           if cur_iface["log_established"].eql?("yes") then
                                             @@LOGGING_ESTABLISHED
                                           else
                                             "ACCEPT"
                                           end
                                         end
      iface_settings[:log_drop] = unless cur_iface.has_key?("log_drop") then
                                    if @default_log_drop then
                                      @@LOGGING_DROPPED
                                    else
                                      "DROP"
                                    end
                                  else
                                    if cur_iface["log_drop"].eql?("yes") then
                                      @@LOGGING_DROPPED
                                    else
                                      "DROP"
                                    end
                                  end
      iface_settings[:log_reject] = unless cur_iface.has_key?("log_rejected") then
                                      if @default_log_rejected then
                                        @@LOGGING_REJECTED
                                      else
                                        "REJECT"
                                      end
                                    else
                                      if cur_iface["log_rejected"].eql?("yes") then
                                        @@LOGGING_REJECTED
                                      else
                                        "REJECT"
                                      end
                                    end
      iface_settings[:log_invalid] = unless cur_iface.has_key?("log_invalid") then
                                       if @default_log_invalid then
                                         @@LOGGING_INVALID
                                       else
                                         "DROP"
                                       end
                                     else
                                       if cur_iface["log_invalid"].eql?("yes") then
                                         @@LOGGING_INVALID
                                       else
                                         "DROP"
                                       end
                                     end
      # create rules to check if traffic is somehow invalid
      check_flags("#{cur_rule}-bad_traffic", iface, iface_settings[:log_invalid]).each do |bad_flag_rule|
        yield bad_flag_rule
      end
      # and check egress and ingress traffic for that bad traffic
      yield "-A INPUT -j #{cur_rule}-bad_traffic"
      yield "-A OUTPUT -j #{cur_rule}-bad_traffic"
      
      # adding custom rules for output
      if cur_iface.has_key?("additional_output_rules")
        cur_iface["additional_output_rules"].split("\n").each do |val|
          yield "-A OUTPUT #{val}"
          end
      end
      # adding custom rules for input
      if cur_iface.has_key?("additional_input_rules")
        cur_iface["additional_input_rules"].split("\n").each do |val|
          yield "-A INPUT #{val}"
        end
      end
      # adding custom rules for forwarding
      if cur_iface.has_key?("additional_forward_rules")
        cur_iface["additional_forward_rules"].split("\n").each do |val|
          yield "-A FORWARD #{val}"
        end
      end
      
      # check if protocols are set to be allowd
      if cur_iface.has_key?("allowed_protocols")
        cur_iface["allowed_protocols"].split.each do |proto|
          create_rule_for_proto iface_settings, ipv, iface, proto do |proto_rule|
            yield proto_rule
          end
        end
      end
      
      # if we dont have any ip set for this interface
      unless cur_iface.has_key?("ip")
        create_rules_for_ip(iface_settings, ipv, iface) do |rule| 
          yield rule
        end
      else
        cur_iface["ip"].split.each do |cur_ip|
          src_ip_str = "-s #{cur_ip}"
          dest_ip_str = "-d #{cur_ip}"
          create_rules_for_ip(iface_settings, ipv, iface, src_ip_str, dest_ip_str) do |rule|
            yield rule  
          end
        end
      end
      create_deny_rules ipv, iface, iface_settings
    end
  end

  #
  def create_rule_for_proto iface_settings, ipv, iface, proto
    # protocol input
    yield "-A INPUT -i #{iface} -p #{proto} -j ACCEPT"
    # protocol output
    yield "-A OUTPUT -o #{iface} -p #{proto} -j ACCEPT"
  end
  
  #
  def create_rules_for_ip iface_settings, ipv, iface, src_ip = nil, dest_ip = nil
    cur_iface = @fw[ipv][iface]
    # allow incoming traffic on ports in @fw.select("/#{ipv}/#{iface}/service_ports_tcp_out") and @fw.select("/#{ipv}/#{iface}/service_ports_udp_out")
    if cur_iface.has_key?("service_ports_tcp_in")
      cur_iface["service_ports_tcp_in"].split.each do |tcp_port|
        # create rule to allow syn packets in and established and related packets in and out for tcp on given tcp port, iface and address
        yield "-A INPUT -p tcp -m limit --limit #{iface_settings[:max_tcp_in_per_second]}/second --limit-burst 10 -m conntrack --ctstate NEW -i #{iface} #{dest_ip} --dport #{tcp_port} -j #{iface_settings[:log_syn_in]}"
        yield "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -p tcp -i #{iface} #{dest_ip} --dport #{tcp_port} -j #{iface_settings[:log_established]}"
        yield "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -p tcp -o #{iface} #{src_ip} --sport #{tcp_port} -j #{iface_settings[:log_established]}"
      end
    end
    if cur_iface.has_key?("service_ports_udp_in")
      cur_iface["service_ports_udp_in"].split.each do |udp_port|
        # create rule to allow packets in and out for udp on given udp port, iface and address
        yield "-A INPUT -p udp -m limit --limit #{iface_settings[:max_udp_in_per_second]}/second --limit-burst 10 -i #{iface} #{dest_ip} --dport #{udp_port} -j #{iface_settings[:log_syn_in]}"
        yield "-A OUTPUT -p udp -o #{iface} #{src_ip} --sport #{udp_port} -j #{iface_settings[:log_established]}"
      end
    end
    # allow outgoing traffic on ports in @fw.select("/#{ipv}/#{iface}/service_ports_tcp_out") and @fw.select("/#{ipv}/#{iface}/service_ports_udp_out")
    if cur_iface.has_key?("service_ports_tcp_out")
      cur_iface["service_ports_tcp_out"].split.each do |tcp_port|
        # create rule to allow syn packets out and established and related packets in and out for tcp on given udp port, iface and address
        yield "-A OUTPUT -p tcp -m limit --limit #{iface_settings[:max_tcp_out_per_second]}/second --limit-burst 10 -m conntrack --ctstate NEW -o #{iface} #{src_ip} --dport #{tcp_port} -j #{iface_settings[:log_syn_out]}"
        yield "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -p tcp -o #{iface} #{src_ip} --dport #{tcp_port} -j #{iface_settings[:log_established]}"
        yield "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -p tcp -i #{iface} #{dest_ip} --sport #{tcp_port} -j #{iface_settings[:log_established]}"
      end
    end
    if cur_iface.has_key?("service_ports_udp_out")
      cur_iface["service_ports_udp_out"].split.each do |udp_port|
        # create rule to allow packets in and out for udp on given udp port, iface and address
        yield "-A OUTPUT -p udp -m limit --limit #{iface_settings[:max_udp_out_per_second]}/second --limit-burst 10 -o #{iface} #{src_ip} --dport #{udp_port} -j #{iface_settings[:log_syn_out]}"
        yield "-A INPUT -p udp -i #{iface} #{dest_ip} --sport #{udp_port} -j #{iface_settings[:log_established]}"
      end
    end
    # depending on ip version we have to use icmp types. lets find out which one we have to use
    ipv_depending_icmp_str = if ipv.eql? "ipv6" then
                               "-p ipv6-icmp --icmpv6-type"
                             else
                               "-p icmp --icmp-type "
                             end
    # allow icmp traffic in and out
    if cur_iface.has_key?("allowed_icmp_types_in")
      cur_iface["allowed_icmp_types_in"].split.each do |icmp_type|
        yield "-A INPUT #{ipv_depending_icmp_str} #{icmp_type} -i #{iface} -m limit --limit #{iface_settings[:max_icmp_in_per_second]}/minute --limit-burst 10 -j #{iface_settings[:log_icmp_in]}"
      end
    end
    if cur_iface.has_key?("allowed_icmp_types_out")
      cur_iface["allowed_icmp_types_out"].split.each do |icmp_type|
        yield "-A OUTPUT #{ipv_depending_icmp_str} #{icmp_type} -o #{iface} -m limit --limit #{iface_settings[:max_icmp_out_per_second]}/minute --limit-burst 10 -j #{iface_settings[:log_icmp_out]}"
      end
    end
  end
  
  #
  def check_flags rule, iface, log
    res = []
    res << "-N #{rule}"
    res << "-F #{rule}"
    res << "-A #{rule} -p tcp --tcp-flags ALL FIN,URG,PSH -i #{iface} -m limit --limit 3/minute -j #{log}"
    res << "-A #{rule} -p tcp --tcp-flags ALL FIN,URG,PSH -i #{iface} -m limit --limit 3/minute -j #{log}"
    res << "-A #{rule} -p tcp --tcp-flags ALL ALL -i #{iface} -m limit --limit 3/minute -j #{log}"
    res << "-A #{rule} -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -i #{iface} -m limit --limit 3/minute -j #{log}"
    res << "-A #{rule} -p tcp --tcp-flags ALL NONE -i #{iface} -m limit --limit 3/minute -j #{log}"
    res << "-A #{rule} -p tcp --tcp-flags SYN,RST SYN,RST -i #{iface} -m limit --limit 3/minute -j #{log}"
    res << "-A #{rule} -p tcp --tcp-flags SYN,FIN SYN,FIN -i #{iface} -m limit --limit 3/minute -j #{log}"
    res
  end

  #
  def initialize_rules
    @init_rules ||= ["-F", "-X",  "-P INPUT DROP", "-P OUTPUT DROP", "-P FORWARD DROP"]
  end
  
  #
  def create_logging_rules
    return @logging_rules if @logging_rules
    @@LOGGING_ICMP_IN = "ICMP_INl "
    @@LOGGING_ICMP_OUT = "ICMP_OUTl "
    @@LOGGING_ESTABLISHED = "ESTABLISHEDl "
    @@LOGGING_ACCEPTED_SYN_IN = "ACCEPTED_SYN_INl "
    @@LOGGING_ACCEPTED_SYN_OUT = "ACCEPTED_SYN_OUTl "
    @@LOGGING_REJECTED = "REJECTEDl "
    @@LOGGING_DROPPED = "DROPPEDl "
    @@LOGGING_INVALID = "INVALIDl "
    
    @logging_rules = []
    # add icmp out
    @logging_rules.concat ["-N #{@@LOGGING_ICMP_IN} 2> /dev/null","-A #{@@LOGGING_ICMP_IN} -j LOG --log-level #{@default_log_level} --log-prefix \"#{@@LOGGING_ICMP_IN}:\"", "-A #{@@LOGGING_ICMP_IN} -j ACCEPT"]
    # add icmp out
    @logging_rules.concat ["-N #{@@LOGGING_ICMP_OUT} 2> /dev/null","-A #{@@LOGGING_ICMP_OUT} -j LOG --log-level #{@default_log_level} --log-prefix \"#{@@LOGGING_ICMP_OUT}:\"", "-A #{@@LOGGING_ICMP_OUT} -j ACCEPT"]
    
    # add accepted logging
    @logging_rules.concat ["-N #{@@LOGGING_ESTABLISHED} 2> /dev/null","-A #{@@LOGGING_ESTABLISHED} -j LOG --log-level #{@default_log_level} --log-prefix \"#{@@LOGGING_ESTABLISHED}:\"", "-A #{@@LOGGING_ESTABLISHED} -j ACCEPT"]
    # add accepted syn in logging
    @logging_rules.concat ["-N #{@@LOGGING_ACCEPTED_SYN_IN} 2> /dev/null","-A #{@@LOGGING_ACCEPTED_SYN_IN} -j LOG --log-level #{@default_log_level} --log-prefix \"#{@@LOGGING_ACCEPTED_SYN_IN}:\"", "-A #{@@LOGGING_ACCEPTED_SYN_IN} -j ACCEPT"]
    # add acceped syn out logging
    @logging_rules.concat ["-N #{@@LOGGING_ACCEPTED_SYN_OUT} 2> /dev/null","-A #{@@LOGGING_ACCEPTED_SYN_OUT} -j LOG --log-level #{@default_log_level} --log-prefix \"#{@@LOGGING_ACCEPTED_SYN_OUT}:\"", "-A #{@@LOGGING_ACCEPTED_SYN_OUT} -j ACCEPT"]
    # add rejected logging
    @logging_rules.concat ["-N #{@@LOGGING_REJECTED} 2> /dev/null","-A #{@@LOGGING_REJECTED} -j LOG --log-level #{@default_log_level} --log-prefix \"#{@@LOGGING_REJECTED}:\"", "-A #{@@LOGGING_REJECTED} -j REJECT"]
    # add dropped logging
    @logging_rules.concat ["-N #{@@LOGGING_DROPPED} 2> /dev/null","-A #{@@LOGGING_DROPPED} -j LOG --log-level #{@default_log_level} --log-prefix \"#{@@LOGGING_DROPPED}:\"", "-A #{@@LOGGING_DROPPED} -j DROP"]
    # add invalid logging
    @logging_rules.concat ["-N #{@@LOGGING_INVALID} 2> /dev/null","-A #{@@LOGGING_INVALID} -j LOG --log-level #{@default_log_level} --log-prefix \"#{@@LOGGING_INVALID}:\"", "-A #{@@LOGGING_INVALID} -j DROP"]
    
    # TODO: extend with xmas scan, syn-fin scan, etc etc 
  end

  #
  def to_s
    if @fw.has_key?("auto_commit_and_save_rules") and @fw["auto_commit_and_save_rules"].eql?("yes")
      # get settings from config
      ipt_save_bin = @fw["iptables-save_bin"]
      ip6t_save_bin = @fw["ip6tables-save_bin"]
      ipt_save_to = @fw["iptables_save_to"]
      ip6t_save_to = @fw["ip6tables_save_to"]
      # execute rules
      configure_system do |sys|
        system("#{sys}")
      end
      @f4.each do |rule|
        system("#{@f4_bin} #{rule}")
      end
      @f6.each do |rule|
        system("#{@f6_bin} #{rule}")
      end
      # save rules
      system("#{ipt_save_bin} > #{ipt_save_to}")
      system("#{ip6t_save_bin} > #{ip6t_save_to}")
      return "commited and saved iptables"
    end
    res = "#!/bin/sh\n"
    res << "\n# printing iptables\n\n"
    configure_system do |sys|
      res << "#{sys}\n"
    end
    @f4.each do |rule|
      res << "#{@f4_bin} #{rule}\n"
    end
    res << "\n# printing ip6tables\n\n"
    @f6.each do |rule|
      res << "#{@f6_bin} #{rule}\n"
    end
    res
  end
end

if __FILE__ == $0
  begin
    fw = Iptables.new ARGV[0]
  rescue Exception=>e
    puts "#{ e.message } - (#{ e.class })" << "\n" << (e.backtrace or []).join("\n")
  end
  puts fw.to_s
end


