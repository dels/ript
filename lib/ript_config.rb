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

end



