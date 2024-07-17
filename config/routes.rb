JwtEngin::Engine.routes.draw do
  root 'home#index'
  resources :auth
end
