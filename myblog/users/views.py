from django.shortcuts import render
from django.views import View
from django.http import response
from django.http import HttpResponse
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection


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

