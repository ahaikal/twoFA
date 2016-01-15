namespace :users do
  desc "This task will generate base32 code for users"
  task generate_code: :environment do
    User.find_each do |user|
      user.update_attributes(second_factor_secure_code: ROTP::Base32.random_base32)
    end
    puts "generate_code done."
  end
end
