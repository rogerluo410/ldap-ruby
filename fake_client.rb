require './active_dir'

role     = RoleInfo.new
username = 'xxx'
passwd   = 'xxx' 

puts 'Search myself'
role.get_role_info(username,passwd,0)
puts role.user_id() 
puts role.full_name()
puts "role:" + role.role().to_s
puts "location:" + role.location().to_s
puts "employee ID:" + role.employeeID().to_s

puts "---"
puts 'Search other people, such as a manager'
role = RoleInfo.new
role.get_role_info(username,passwd,'GivenName FamilyName',1)

puts role.user_id()
puts role.full_name()
puts "role:" + role.role().to_s
puts "location:" + role.location().to_s
puts "employee ID:" + role.employeeID().to_s

