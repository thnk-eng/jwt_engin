class AddShopifyFieldsToUsers < ActiveRecord::Migration[7.1]
  def change
    add_column :jwt_engin_users, :shopify_customer_id, :string
    add_column :jwt_engin_users, :shop_domain, :string
    add_index :jwt_engin_users, :shop_domain
    add_index :jwt_engin_users, :shopify_customer_id
  end
end
