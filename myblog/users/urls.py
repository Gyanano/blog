# 子应用的路由管理
from django.urls import path

from users.views import RegisterView, ImageCodeView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('imagecode/', ImageCodeView.as_view(), name='imagecode'),

]
