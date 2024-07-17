Rails.application.routes.draw do
  mount JwtEngin::Engine => "/jwt_engin"
end
