import redis
from django.shortcuts import render
from django.views import View
from django.http import response
from django.http import HttpResponse
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection
from utils.response_code import RETCODE
import logging
from random import randint
from libs.yuntongxun.sms import CCP

ccp = CCP()

logger = logging.getLogger('django')


# Create your views here.
# 注册视图
class RegisterView(View):

    def get(self, request):
        return render(request, 'register.html')


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
        phone_number = request.GET.get('phone_number')
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
        ccp.send_template_sms(phone_number, [sms_code, 5], 1)
        return response.JsonResponse({'code': RETCODE.OK, 'errmsg': '短信发送成功'})
