from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.
class User(AbstractUser):
    # 手机号 blank=False表示不能为空
    phone_number = models.CharField(max_length=11, unique=True, blank=False)
    # 头像
    avatar = models.ImageField(upload_to='avatar/%Y%m%d/', blank=True)
    # 简介信息
    user_desc = models.CharField(max_length=500, blank=True)

    USERNAME_FIELD = 'phone_number'

    # 创建超级管理员的需要必须输入的字段
    REQUIRED_FIELDS = ['username', 'email']

    class Meta:
        db_table = 'tb_users'  # 修改表名
        verbose_name = '用户管理'  # admin后台显示
        verbose_name_plural = verbose_name  # admin后台显示

    def __str__(self):
        return self.phone_number
