# ActiveDirectoryUser (active_dir_server.rb)
# Author       : Ernie Miller
# modify       : Roger Luo
# Last modified: 10/9/2014
#
# Description:
#   A class for authenticating via Active Directory and providing
#   more developer-friendly access to key user attributes through configurable
#   attribute readers.
#
#   You might find this useful if you want to use a central user/pass from AD
#   but still keep a local DB cache of certain user details for use in foreign
#   key constraints, for instance.
#
# Configuration:
#   Set your server information below, then add attributes you are interested
#   in to the ATTR_SV or ATTR_MV hashes, depending on whether they are single
#   or multi-value attributes. The left hand side is your desired name for
#   the attribute, and the right hand side is the attribute name as it exists
#   in the directory.
#
#   An optional Proc can be supplied to perform some processing on the raw
#   directory data before returning it. This proc should accept a single
#   parameter, the value to be processed. It will be used in Array#collect
#   for multi-value attributes.
#
#   Example:
#     :flanderized_first_name => [ :givenname,
#                                  Proc.new {|n| n + '-diddly'} ]
#
# Usage:
#   user = ActiveDirectoryUser.authenticate('emiller','password')
#   user.first_name # => "Ernie"
#   user.flanderized_first_name # => "Ernie-diddly"
#   user.groups     # => ["Mac Users", "Geeks", "Ruby Coders", ... ]

require 'rubygems'
require 'net/ldap' # gem install net-ldap

SUCCESS_CODE            = 0   # Return correct
CONNECTION_FAILURE_CODE = 1   # Connect to AD failed
SEARCH_FAILURE_CODE     = 2   # Search cn of AD failed
OTHER_EX_CODE           = 3   # Other exceptions

class ReturnObj
 @return_code
 @return_msg
 @user

 def initialize(code,msg,user)
     @return_code = code
     @return_msg  = msg
     @user        = user
 end

 attr_writer:return_code
 attr_reader:return_code

 attr_writer:return_msg
 attr_reader:return_msg

 attr_writer:user
 attr_reader:user

end #ReturnObj


class ActiveDirServer

  ### BEGIN CONFIGURATION ###
  SERVER = 'scrootdc07.vmware.com'   # Active Directory server name or IP
  PORT   = 389                       # Active Directory server port (default 389)
  BASE   = 'DC=vmware,DC=com'        # Base to search from
  DOMAIN = 'vmware.com'              # For simplified user@domain format login

  # ATTR_SV is for single valued attributes only. Generated readers will
  # c onvert th e value to a string before returning or calling your Proc.
  ATTR_SV = {
              :login      => :samaccountname,
              :first_name => :givenname,
              :last_name  => :sn,
              :email      => :mail
             }


  # ATTR_MV is for multi-valued attributes. Generated readers will always
  # retu rn a n array.
  ATTR_MV = {
              :groups => [ :memberof,
                           # Get the simplified name of first-level groups.
                             # TODO: Handle escaped special characters
                             Proc.new {|g| g.sub(/.*?CN=(.*?),.*/, '\1')} ]
              }

  # Expo sing the raw Net::LDAP::Entry is probably overkill, but could be set
  # up by uncommenting the line below if you disagree.
  # at tr_reader :entry

  ### END CONFIGURATION ###

  #  Automatically fail login if login or password are empty. Otherwise, try
  # to initialize a Net::LDAP object and call its bind method. If successful,
  # we find the LDAP entry for the user and initialize with it. Returns nil
  # on failure.
  def self.authenticate(login, pass, searchname, switch = 0)
    return nil if login.empty? or pass.empty?
    conn = Net::LDAP.new :host => SERVER,
                         :port => PORT,
                         :base => BASE,
                         :auth => {
                                   :username => "#{login}@#{DOMAIN}",
                                   :password => pass,
                                   :method   => :simple
                                   }
    retval = ReturnObj.new(CONNECTION_FAILURE_CODE,"Access AD failure",nil)

    #conn.auth userName,pass
    if !conn.bind
       return retval
    end
 
      
    if switch == 0 
       user_list = conn.search(:filter => "sAMAccountName=#{login}")
    else
       user_list = conn.search(:filter => "cn=" + searchname)
    end 
    
    if user_list.size == 0 
       retval.return_code = (SEARCH_FAILURE_CODE)
       retval.return_msg  = ("Fetch data failed")
       retval.user        = (nil)
       return retval     
    end
    user_list.map do | user |    
       if user and /Close/.match(user.distinguishedName().first) == nil
          retval.return_code = (SUCCESS_CODE)
          retval.return_msg  = ("Fetch data successful")
          retval.user        = (user)
          return retval
       end
    end # do
     # If we don't rescue this, Net::LDAP is decidedly ungraceful about failing
       # to conn ect to the server. We'd prefer to say authentication failed.
    rescue Net::LDAP::LdapError => e
      retval.return_code = (OTHER_EX_CODE)
      retval.return_msg  = (e)
      retval.user        = (nil) 
      return retval
  end

  def full_name
    self.first_name + ' ' + self.last_name
  end

  def member_of?(group)
    self.groups.include?(group)
  end

  private

  def initialize(entry)
    @entry = entry
    self.class.class_eval do
      generate_single_value_readers
      generate_multi_value_readers
    end
  end

  def self.generate_single_value_readers
    ATTR_SV.each_pair do |k, v|
      val, block = Array(v)
      define_method(k) do
         if @entry.attribute_names.include?(val)
           if block.is_a?(Proc)
            return block[@entry.send(val).to_s]
          else
            return @entry.send(val).to_s
          end
        else
          return ''
        end
       end
    end
  end

  def self.generate_multi_value_readers
    ATTR_MV.each_pair do |k, v|
      val, block = Array(v)
      define_method(k) do
        if @entry.attribute_names.include?(val)
          if block.is_a?(Proc)
            return @entry.send(val).collect(&block)
          else
            return @entry.send(val)
          end
        else
          return []
        end
      end
    end
  end
end

