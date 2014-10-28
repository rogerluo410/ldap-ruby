require './active_dir_server'
require 'logger'
require 'json/pure'

class RoleInfo
   @user_id
   @full_name
   @role_id
   @employeeID
   @role     
   @location  
   def initialize()
       @user_id    = ""
       @full_name  = ""
       @role_id    = ""
       @employeeID = ""
       @role       = ""
       @location   = ""
   end

   attr_writer:user_id
   attr_reader:user_id
   
   attr_writer:full_name
   attr_reader:full_name
 
   attr_writer:role_id
   attr_reader:role_id
  
   attr_writer:role
   attr_reader:role

   attr_writer:employeeID
   attr_reader:employeeID

   attr_writer:location
   attr_reader:location

   def Log(s = "#{$!.message} #{$@[0]} ")
      return if not s
      logger = Logger.new("adproxy.log."+(Time.now).strftime("%Y%m%d"), 'daily') #daily/weekly/monthly.                                  #logger output level is DEBUG  Logs and Terminal
      logger.level = Logger::DEBUG
      p s
      logger.debug(''){s}
      logger.close
   end


   def get_role_info(username,password,searchname,switch)
       retval = ActiveDirServer.authenticate(username,password,searchname,switch)
       #Log(retval.user())
       if retval.return_code() == SUCCESS_CODE
          @user_id    = retval.user().sAMAccountName()
          @full_name  = retval.user().name()
          @employeeID = retval.user().employeeID()
          @location   = retval.user().st()
          @role       = retval.user().extensionAttribute2()
       end
       return retval.return_code()
   end

end # RoleInfo
