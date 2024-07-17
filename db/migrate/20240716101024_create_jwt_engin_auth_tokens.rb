class CreateJwtEnginAuthTokens < ActiveRecord::Migration[7.1]
  def change
    create_table :jwt_engin_auth_tokens, id: :uuid do |t|
      t.string :secret_token
      t.string :token
      t.references :jwt_engin_user, foreign_key: true, type: :uuid

      t.timestamps
    end
    add_index :jwt_engin_auth_tokens, :secret_token, unique: true
    add_index :jwt_engin_auth_tokens, :token, unique: true
  end
end
