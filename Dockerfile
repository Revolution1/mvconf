FROM python:2.7

WORKDIR /root/

RUN pip install --no-cache-dir pyinstaller -i https://pypi.tuna.tsinghua.edu.cn/simple \
	&& rm -rf /usr/mvconf/python ~/.cache

ADD requirements.pip /root/

RUN pip install --no-cache-dir -r requirements.pip -i https://pypi.tuna.tsinghua.edu.cn/simple
