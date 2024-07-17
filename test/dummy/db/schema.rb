# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[7.1].define(version: 2024_07_17_203850) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pgcrypto"
  enable_extension "plpgsql"

  create_table "fuse_recommendations", force: :cascade do |t|
    t.string "subject_type", null: false
    t.bigint "subject_id", null: false
    t.string "item_type", null: false
    t.bigint "item_id", null: false
    t.string "context", null: false
    t.float "score", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["item_type", "item_id", "context"], name: "index_fuse_recommendations_on_item_and_context"
    t.index ["item_type", "item_id"], name: "index_fuse_recommendations_on_item"
    t.index ["subject_type", "subject_id", "context"], name: "index_fuse_recommendations_on_subject_and_context"
    t.index ["subject_type", "subject_id"], name: "index_fuse_recommendations_on_subject"
  end

  create_table "future_categories", force: :cascade do |t|
    t.string "name"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "future_users", force: :cascade do |t|
    t.string "name"
    t.string "email"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "jinn_printful_products_new_products", force: :cascade do |t|
    t.string "external_id"
    t.string "name"
    t.string "image_url"
    t.string "variant_id"
    t.decimal "retail_price"
    t.string "sku"
    t.string "files"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "jwt_engin_accounts", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "jwt_engin_auth_tokens", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "secret_token"
    t.string "token"
    t.uuid "jwt_engin_user_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["jwt_engin_user_id"], name: "index_jwt_engin_auth_tokens_on_jwt_engin_user_id"
    t.index ["secret_token"], name: "index_jwt_engin_auth_tokens_on_secret_token", unique: true
    t.index ["token"], name: "index_jwt_engin_auth_tokens_on_token", unique: true
  end

  create_table "jwt_engin_users", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "email"
    t.string "confirmation_token"
    t.datetime "confirmed_at"
    t.datetime "confirmation_sent_at"
    t.string "unconfirmed_email"
    t.integer "role"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "shopify_customer_id"
    t.string "shop_domain"
    t.index ["confirmation_token"], name: "index_jwt_engin_users_on_confirmation_token", unique: true
    t.index ["email"], name: "index_jwt_engin_users_on_email", unique: true
    t.index ["shop_domain"], name: "index_jwt_engin_users_on_shop_domain"
    t.index ["shopify_customer_id"], name: "index_jwt_engin_users_on_shopify_customer_id"
  end

  create_table "jwt_ngin_auth_tokens", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "secret_token"
    t.string "token"
    t.uuid "jwt_ngin_user_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["jwt_ngin_user_id"], name: "index_jwt_ngin_auth_tokens_on_jwt_ngin_user_id"
    t.index ["secret_token"], name: "index_jwt_ngin_auth_tokens_on_secret_token", unique: true
    t.index ["token"], name: "index_jwt_ngin_auth_tokens_on_token", unique: true
  end

  create_table "jwt_ngin_users", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "email"
    t.string "shopify_id"
    t.string "confirmation_token"
    t.datetime "confirmed_at"
    t.datetime "confirmation_sent_at"
    t.string "unconfirmed_email"
    t.integer "role"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["confirmation_token"], name: "index_jwt_ngin_users_on_confirmation_token", unique: true
    t.index ["email"], name: "index_jwt_ngin_users_on_email", unique: true
    t.index ["shopify_id"], name: "index_jwt_ngin_users_on_shopify_id", unique: true
  end

  create_table "knowledge_base_advanceds", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_algorithmic_tradings", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_applications", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_basics", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_budgetings", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_corps", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_creations", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_cryptos", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_forms", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_formulas", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_incs", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_investings", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_iots", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_llcs", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_pentestings", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_researches", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_resources", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_securities", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_softwares", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_startups", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_stocks", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_tools", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_tradings", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "knowledge_base_web_devs", force: :cascade do |t|
    t.string "name"
    t.text "content"
    t.string "file"
    t.string "image_url"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "ocean_spray_processed_files", force: :cascade do |t|
    t.string "name"
    t.string "file_type"
    t.integer "size"
    t.boolean "processed"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "prod_dev_barcodes", force: :cascade do |t|
    t.string "data"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "rubychain_ngin_printful_products", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.bigint "printful_id"
    t.bigint "external_id"
    t.string "name"
    t.text "description"
    t.string "thumbnail_url"
    t.boolean "is_ignored"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "rubychain_ngin_product_responses", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.jsonb "data"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "rubychain_ngin_thnk_products", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "handle"
    t.string "title"
    t.text "body"
    t.string "vendor"
    t.text "product_category"
    t.text "tags"
    t.boolean "published", default: false
    t.string "option_one_name"
    t.string "option_one_value"
    t.string "option_two_name"
    t.string "option_two_value"
    t.string "option_three_name"
    t.string "option_three_value"
    t.string "variant_sku"
    t.decimal "variant_grams"
    t.string "variant_inventory_tracker"
    t.string "variant_inventory_policy", null: false
    t.string "variant_fulfillment_service"
    t.decimal "variant_price"
    t.decimal "variant_compare_at_price"
    t.boolean "variant_requires_shipping", default: true, null: false
    t.boolean "variant_taxable", default: true, null: false
    t.string "variant_barcode"
    t.text "image_src"
    t.integer "image_position", default: 1
    t.boolean "gift_card", default: false, null: false
    t.string "seo_title"
    t.text "seo_description"
    t.string "variant_image"
    t.string "variant_weight_unit"
    t.string "variant_tax_code"
    t.decimal "cost_per_item"
    t.decimal "price_international"
    t.decimal "compare_at_price_international"
    t.string "product_collection"
    t.string "status", default: "active", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "snp_integration_api_v1_printful_products_create_single_products", force: :cascade do |t|
    t.string "external_id"
    t.string "name"
    t.string "image_url"
    t.string "variant_id"
    t.decimal "retail_price"
    t.string "sku"
    t.string "files"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "upload_ngin_documents", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "upload_ngin_upload_shopifies", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  add_foreign_key "jwt_engin_auth_tokens", "jwt_engin_users"
  add_foreign_key "jwt_ngin_auth_tokens", "jwt_ngin_users"
end
