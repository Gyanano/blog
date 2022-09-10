"""myblog URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

# # 导入系统的logging
# import logging
# from django.http import HttpResponse
#
# # 获取日志器
# logger = logging.getLogger('django')


urlpatterns = [
    path('admin/', admin.site.urls),
    # include参数中,需要先设置一个元组urlconf_module, app_name
    # urlconf_module为子应用的路由
    # app_name为子应用的名字
    # namespace为命名空间,确保两个同名的urls不冲突
    path('', include(('users.urls', 'users'), namespace='users')),
]
