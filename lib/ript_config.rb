# -*- coding: utf-8 -*-

require "json"

class RIPTConfig

  def initialize(cfg=nil)
    cfg ||= "./ript.json"
    # load config file
    raise "configuration file must be readable" unless File.exist? cfg and File.file? cfg and File.readable? cfg
    raise "could not load configuration file" unless (@fw = JSON.parse(File.read(cfg)))
  end
  
  def conf(cfg=nil)
    initialize(cfg) unless @fw
    @fw
  end

  def f4_bin
    @f4_bin = @fw['iptables_bin'] unless  @f4_bin
    @f4_bin
  end

  def f6_bin
    @f6_bin = @fw['ip6tables_bin'] unless @f6_bin
    @f6_bin
  end
  
end



