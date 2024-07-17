class CreateJwtEnginAccounts < ActiveRecord::Migration[7.1]
  def change
    create_table :jwt_engin_accounts, id: :uuid do |t|
      # t.references :jwt_engin_user
      t.timestamps
    end
  end
end
