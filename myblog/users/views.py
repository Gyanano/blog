import redis
from django.db import DatabaseError
from django.shortcuts import render
from django.views import View
from django.http import response
from django.http import HttpResponse
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection

from users.models import User
from utils.response_code import RETCODE
import re
import logging
from random import randint
from libs.yuntongxun.sms import CCP
from django.shortcuts import redirect
from django.urls import reverse

logger = logging.getLogger('django')


# Create your views here.
# 注册视图
class RegisterView(View):

    def get(self, request):
        return render(request, 'register.html')

    def post(self, request):
        """
        1.接收数据
        2.验证数据
            2.1参数是否齐全
            2.2手机号格式是否正确
            2.3密码是否符合格式
            2.4密码是否一致
            2.5短信验证码是否跟redis一致
        3.保存注册信息
        4.返回响应
        :param request:
        :return:
        """
        phone_number = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        sms_code = request.POST.get('sms_code')
        if not all([phone_number, password, password2, sms_code]):
            return response.HttpResponseBadRequest('缺少必要的参数')
        if not re.match('^1[3-9]\d{9}$', phone_number):
            return response.HttpResponseBadRequest('手机号不符合规则')
        if not re.match('^[0-9A-Za-z]{8,20}', password):
            return response.HttpResponseBadRequest('请输入8-20位的密码,且密码只能是数字或字母')
        if password != password2:
            return response.HttpResponseBadRequest('两次密码输入不一致')
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get(f'sms:{phone_number}').decode()
        if redis_sms_code is None:
            return response.HttpResponseBadRequest('短信验证码已过期')
        if sms_code != redis_sms_code:
            return response.HttpResponseBadRequest('短信验证码错误')
        # 保存用户信息
        try:
            user = User.objects.create_user(username=phone_number, phone_number=phone_number, password=password)
        except DatabaseError as e:
            logger.error(e)
            return response.HttpResponseBadRequest('注册失败')
        # return HttpResponse('注册成功')
        from django.contrib.auth import login
        login(request, user)
        # reverse可以通过namespace:name来获取到对应的路由
        res = redirect(reverse('home:index'))
        res.set_cookie('is_login', True)
        res.set_cookie('username', user.username, max_age=24 * 7 * 3600)

        return res


class ImageCodeView(View):

    def get(self, request):
        """
        1.receive the uuid from the client
        2.to check if the uuid has been received
        3.use the captcha to generate a verification code(is the binary type of picture)
        4.save the picture content to redis
            the key is the uuid, and the value is the binary type of picture
        5.return the binary type of picture to client
        :param request:
        :return:
        """
        uuid = request.GET.get('uuid')
        if uuid is None:
            return response.HttpResponseBadRequest('缺少必要参数!')
        text, img = captcha.generate_captcha()
        # 链接redis
        redis_conn = get_redis_connection('default')
        # redis_conn.setex(key(键), seconds(过期的秒数), value(值))
        redis_conn.setex(f'img:{uuid}', 300, text)
        return HttpResponse(img, content_type='image/jpeg')


class SmsCodeView(View):
    def get(self, request):
        """
        1.接收参数
        2.检验参数
            2.1参数是否齐全
            2.2图片验证码的验证
                连接redis获取redis中的图片验证码
                判断图片验证码是否存在
                如果没过期,获取后可以把原图片验证码删了
                比对图片验证码(忽略大小写)
        3.生成短信验证码
        4.保存短信验证码到redis中
        5.发送短信
        6.返回相应
        :param request:
        :return:
        """
        phone_number = request.GET.get('mobile')
        image_code = request.GET.get('image_code')
        uuid = request.GET.get('uuid')
        if not all([phone_number, image_code, uuid]):
            return response.JsonResponse({'code': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少必要的参数'})
        redis_conn = get_redis_connection('default')
        redis_image_code = redis_conn.get(f'img:{uuid}')
        if redis_image_code is None:
            return response.JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码已过期'})
        try:
            redis_conn.delete(f'img:{uuid}')
        except Exception as e:
            logger.error(e)
        if redis_image_code.decode().lower() != image_code.lower():
            return response.JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码错误'})
        # 生成短信验证码
        sms_code = f'{randint(0, 999999):06d}'
        logger.info(sms_code)
        redis_conn.setex(f'sms:{phone_number}', 300, sms_code)
        CCP().send_template_sms(phone_number, [sms_code, 5], 1)
        return response.JsonResponse({'code': RETCODE.OK, 'errmsg': '短信发送成功'})


class LoginView(View):

    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        """
        1.接收参数
        2.验证参数
            2.1手机号是否合法
            2.2密码是否合法
        3.用户认证登录
        4.状态的保持
        5.根据用户选择的是否记住登录状态进行判断
        6.为了首页的提示, 我们需要设置一些cookie信息
        7.返回响应
        :param request:
        :return:
        """
        phone_number = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')
        if not re.match('^1[3-9]\d{9}$', phone_number):
            return response.HttpResponseBadRequest('手机号不符合规则')
        if not re.match('^[0-9A-Za-z]{8,20}', password):
            return response.HttpResponseBadRequest('密码不符合规则')
        from django.contrib.auth import authenticate
        user = authenticate(phone_number=phone_number, password=password)
        if user is None:
            return response.HttpResponseBadRequest('用户名或密码错误')
        from django.contrib.auth import login
        login(request, user)
        res = redirect(reverse('home:index'))
        if remember != 'on':
            # 0表示浏览器关闭后释放
            request.session.set_expiry(0)
            res.set_cookie('is_login', True)
            res.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        else:
            # 默认是记住两周
            request.session.set_expiry(None)
            res.set_cookie('is_login', True, max_age=14 * 24 * 3600)
            res.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        return res


from django.contrib.auth import logout


class LogoutView(View):
    def get(self, request):
        logout(request)
        res = redirect(reverse('home:index'))
        res.delete_cookie('is_login')
        res.delete_cookie('username')
        return res
