JwtEngin::Engine.routes.draw do
  root 'home#index'
  post 'login', to: 'auth#create'
  delete 'logout', to: 'auth#destroy'
  post 'signup', to: 'users#create'
end
