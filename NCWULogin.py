import random
import re

import execjs
import requests


def js_from_file(file_name):
    """
    读取js文件
    :return:
    """
    with open(file_name, 'r', encoding='UTF-8') as file:
        result = file.read()
    return result


class NCWULogin:
    """
    华水教务登录工具类
    """

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, "
                          "like Gecko) Chrome/87.0.4280.67 Safari/537.36",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "accept": "text/plain, */*; q=0.01",
            "x-requested-with": "XMLHttpRequest",
            "origin": "https: // jwmis.ncwu.edu.cn",
            "referer": "https: // jwmis.ncwu.edu.cn / hsjw / cas / login.action"
        }

    # 校外登录过统一验证平台
    def getTicket(self):
        """
        通过统一验证平台所需参数详解
        data = {
            '_eventId': 'submit', // 固定
            'username': username,// 你的用户名(学号
            "password": encryptPassword, // 密码(加盐后
            "execution": execution,// 未知参数(应该是防csrf?
            'cllt': 'userNameLogin',// 固定
            'dllt': 'generalLogin',// 固定
            'captcha': captcha,// 验证码(频繁登录时需要
            "lt": "" // 固定为空
        }
        :return:身份认证参数client_vpn_ticket
        """
        # -execution:
        r = self.session.get(
            url="https://authserver.ncwu.edu.cn/authserver/login?service=https%3A%2F%2Fsec.ncwu.edu.cn%2Frump_frontend"
                "%2FloginFromCas%2F")
        execution = re.search('name="execution" value="(.*?)"', r.text).group(1)
        # 获取密码将加的盐值(备用
        salt = re.search('id="pwdEncryptSalt" value="(.*?)"', r.text).group(1)
        # -password:
        context = execjs.compile(js_from_file("./js/encrypt.js"))
        encryptPassword = context.call("encryptPassword", self.password, salt)
        # -captcha:
        # 是否需要验证码(默认不需要，需要自己写
        c = self.session.get(
            url="https://authserver.ncwu.edu.cn/authserver/checkNeedCaptcha.htl?username=" + self.username).json()
        captcha = "" if c["isNeed"] else "你写的验证码识别函数"
        # 封装发送
        data = {
            '_eventId': 'submit',
            'username': self.username,
            "password": encryptPassword,
            "execution": execution,
            'cllt': 'userNameLogin',
            'dllt': 'generalLogin',
            'captcha': captcha,
            "lt": ""
        }
        self.session.post(url="https://authserver.ncwu.edu.cn/authserver/login", data=data)
        return self.session.cookies.get("client_vpn_ticket")

    def getSession(self):
        """
        通过教务系统所需参数详解
        data = {
            'param': '',
            'token': '',
            "timestamp": ,
        }
        以上将统一加密返回为字符串格式
        通过JS逆向浅浅研究一下他们的加密流程可知需要以下参数
        randnumber:验证码
        username:用户名
        password:密码
        passwordPolicy:密码是否合规
        txt_mm_expression:密码规则
        txt_mm_length:密码长度
        txt_mm_userzh:密码是否包含用户名
        hid_flag:是否有验证码（默认1 没有
        将用于他们加密的js代码考皮下来
        狠狠的加密
        最后带着他们发送一个POST请求
        拿到通过验证的session
        :return:通过教务系统验证的session
        """
        # 导进来加密js文件
        context = execjs.compile(js_from_file("./js/jiaowu.js"))
        # 来份待会将要激活的session
        self.session.get(url="https://jwmis.ncwu.edu.cn/hsjw/cas/login.action")
        # 所有参数
        randnumber = ""
        passwordPolicy = str(context.call("isPasswordPolicy", self.username, self.password))
        txt_mm_expression = str(context.call("checkpwd", self.password))
        txt_mm_length = str(len(self.password))
        txt_mm_userzh = str(context.call("checkpwd1", self.username, self.password))
        hid_flag = "1"
        # 修饰加密
        p_username = "_u" + randnumber
        p_password = "_p" + randnumber
        username = context.call("base64encode",
                                self.username + ";;" + self.session.cookies.get(name="JSESSIONID",
                                                                                domain="jwmis.ncwu.edu.cn"))
        password = context.call("newbee", self.password, randnumber)
        params = p_username + "=" + username + "&" + p_password + "=" + password + "&randnumber=" + randnumber + "&isPasswordPolicy=" + passwordPolicy + "&txt_mm_expression=" + txt_mm_expression + "&txt_mm_length=" + txt_mm_length + "&txt_mm_userzh=" + txt_mm_userzh + "&hid_flag=" + hid_flag + "&hidlag=1 "
        r = self.session.get(
            url="https://jwmis.ncwu.edu.cn/hsjw/custom/js/SetKingoEncypt.jsp?random=" + str(random.random()))
        deskey = re.search("var _deskey = '(.*?)'", r.text).group(1)
        nowtime = re.search("var _nowtime = '(.*?)'", r.text).group(1)
        data = context.call("getEncParams", params, nowtime, deskey)
        print(self.session.post(url="https://jwmis.ncwu.edu.cn/hsjw/cas/logon.action", data=data).text)
        return self.session.cookies.get("JSESSIONID")


if __name__ == "__main__":
    # 来个个对象
    testLogin = NCWULogin(username="20223323", password="233333")
    try:
        print(testLogin.getTicket())
        print(testLogin.getSession())
    except:
        print("嗯哼，爆红了吧")
    # ps...拿到这两个参数就可以做你想做的力(我不好说
