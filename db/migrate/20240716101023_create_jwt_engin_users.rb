class CreateJwtEnginUsers < ActiveRecord::Migration[7.1]
  def change
    create_table :jwt_engin_users, id: :uuid do |t|
      t.string :email
      t.string :shopify_id
      t.string :confirmation_token
      t.datetime :confirmed_at
      t.datetime :confirmation_sent_at
      t.string :unconfirmed_email
      t.integer :role

      t.timestamps
    end
    add_index :jwt_engin_users, :email, unique: true
    add_index :jwt_engin_users, :shopify_id, unique: true
    add_index :jwt_engin_users, :confirmation_token, unique: true
  end
end
