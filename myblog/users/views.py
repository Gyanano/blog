import redis
from django.db import DatabaseError
from django.shortcuts import render
from django.views import View
from django.http import response
from django.http import HttpResponse

from home.models import ArticleCategory, Article
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
from django.contrib.auth import logout
from django.contrib.auth.mixins import LoginRequiredMixin

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

        next_page = request.GET.get('next')
        # print(next_page)
        if next_page:
            res = redirect(next_page)
        else:
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


class LogoutView(View):
    def get(self, request):
        logout(request)
        res = redirect(reverse('home:index'))
        res.delete_cookie('is_login')
        return res


class ForgetPasswordView(View):

    def get(self, request):
        return render(request, 'forget_password.html')

    def post(self, request):
        # 接收参数
        phone_number = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')

        # 判断参数是否齐全
        if not all([phone_number, password, password2, smscode]):
            return response.HttpResponseBadRequest('缺少必传参数')

        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', phone_number):
            return response.HttpResponseBadRequest('请输入正确的手机号码')

        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return response.HttpResponseBadRequest('请输入8-20位的密码')

        # 判断两次密码是否一致
        if password != password2:
            return response.HttpResponseBadRequest('两次输入的密码不一致')

        # 验证短信验证码
        redis_conn = get_redis_connection('default')
        sms_code_server = redis_conn.get(f'sms:{phone_number}')
        if sms_code_server is None:
            return response.HttpResponseBadRequest('短信验证码已过期')
        if smscode != sms_code_server.decode():
            return response.HttpResponseBadRequest('短信验证码错误')

        # 根据手机号查询数据
        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            # 如果该手机号不存在，则注册个新用户
            try:
                User.objects.create_user(username=phone_number, phone_number=phone_number, password=password)
            except Exception as e:
                logger.error(e)
                return response.HttpResponseBadRequest('修改失败，请稍后再试')
        else:
            # 修改用户密码
            user.set_password(password)
            user.save()

        # 跳转到登录页面
        res = redirect(reverse('users:login'))

        return res


class UserCenterView(LoginRequiredMixin, View):
    def get(self, request):
        # 获取用户信息
        user = request.user

        # 组织模板渲染数据
        context = {
            'username': user.username,
            'phone_number': user.phone_number,
            'avatar': user.avatar.url if user.avatar else None,
            'user_desc': user.user_desc
        }
        return render(request, 'center.html', context=context)

    def post(self, request):
        # 接收数据
        user = request.user
        avatar = request.FILES.get('avatar')
        username = request.POST.get('username', user.username)
        user_desc = request.POST.get('desc', user.user_desc)

        # 修改数据库数据
        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return response.HttpResponseBadRequest('更新失败，请稍后再试')

        # 返回响应，刷新页面
        res = redirect(reverse('users:center'))
        # 更新cookie信息
        res.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        return res


class WriteBlogView(LoginRequiredMixin, View):
    def get(self, request):
        # 获取博客分类信息
        categories = ArticleCategory.objects.all()

        context = {
            'categories': categories
        }
        return render(request, 'write_blog.html', context=context)

    def post(self, request):
        # 接收数据
        avatar = request.FILES.get('avatar')
        title = request.POST.get('title')
        category_id = request.POST.get('category')
        tags = request.POST.get('tags')
        summary = request.POST.get('summary')
        content = request.POST.get('content')
        user = request.user

        # 验证数据是否齐全
        if not all([avatar, title, category_id, summary, content]):
            return response.HttpResponseBadRequest('参数不全')

        # 判断文章分类id数据是否正确
        try:
            article_category = ArticleCategory.objects.get(id=category_id)
        except ArticleCategory.DoesNotExist:
            return response.HttpResponseBadRequest('没有此分类信息')

        # 保存到数据库
        try:
            article = Article.objects.create(
                author=user,
                avatar=avatar,
                category=article_category,
                tags=tags,
                title=title,
                summary=summary,
                content=content
            )
        except Exception as e:
            logger.error(e)
            return response.HttpResponseBadRequest('发布失败，请稍后再试')

        # 返回响应，跳转到文章详情页面
        # 暂时先跳转到首页
        return redirect(reverse('home:index'))
