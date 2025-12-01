FROM debian

RUN apt update && apt install -y bind9 dnsutils iputils-ping locales \
    && sed -i 's/# ru_RU.UTF-8 UTF-8/ru_RU.UTF-8 UTF-8/' /etc/locale.gen \
    && locale-gen \
    && update-locale LANG=ru_RU.UTF-8 \
    && echo 'root:qwer' | chpasswd

COPY ./mt.ru /var/cache/bind/mt.ru

RUN useradd --create-home --base-dir /home --shell /bin/bash debian \
    && echo "debian:qwer" | chpasswd \
    && usermod -aG sudo debian

EXPOSE 22 53
