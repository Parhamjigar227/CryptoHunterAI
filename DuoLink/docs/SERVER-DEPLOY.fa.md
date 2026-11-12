# راه‌اندازی سرور DuoLink — راهنمای فارسی

این راهنما برای کسی است که می‌خواهد روش **«اتصال از راه دور با کد»** را واقعاً روی
اینترنت کار بیندازد. روش QR به هیچ سروری نیاز ندارد و این راهنما برای آن لازم نیست.

---

## آنچه سرور انجام می‌دهد و آنچه نمی‌تواند بکند

سرور signaling یک «پستچی» است. کلیدها روی گوشی‌ها می‌مانند و سرور فقط پیام‌های
رمزنگاری‌شده را جابه‌جا می‌کند.

| سرور می‌تواند | سرور نمی‌تواند |
|---|---|
| زمان و حجم پیام‌ها را ببیند (متادیتا) | محتوای پیام‌ها را بخواند (AES-256-GCM سرتاسری) |
| کد فعال‌سازی را به‌صورت **هش با فلفل** ببیند | کد را به‌صورت متن خام ببیند (`storesPlaintextActivationCode: false`) |
| کلید عمومی طرفین را ببیند | کلید خصوصی را ببیند (`storesPrivateKeys: false`) |
| امضای ACK را تأیید کند | متن نامه‌های رمزنگاری‌شده را باز کند (`decryptsCommitCiphertext: false`) |

این ادعاها در خود سرور با یک endpoint قابل بررسی‌اند:

```bash
curl https://YOUR-SERVER/v1/server-info
```

---

## پیش‌نیاز

- **Node.js نسخهٔ ۲۲.۵ یا بالاتر** (بخاطر `node:sqlite`؛ نسخه‌های قدیمی‌تر خطا می‌دهند)
- یک دامنه یا زیردامنه که به سرور اشاره کند
- گواهی TLS معتبر (Let's Encrypt رایگان است)

> **چرا TLS الزامی است؟** نسخهٔ نهایی برنامه فقط `https://` را می‌پذیرد. این
> سیاست در `SignalingEndpointPolicy` کد شده و با تست پوشش داده شده است.

---

## ۱. متغیر محیطی فلفل (اجباری)

```bash
export DUOLINK_ACTIVATION_PEPPER="$(openssl rand -hex 32)"
```

این مقدار باید **محرمانه** بماند و در git نرود. اگر گمش کنید، کدهای فعال در آن
لحظه بی‌اعتبار می‌شوند (نه اینکه امنیت بشکند).

> **چرا این متغیر حذف‌شدنی نیست؟** کد ۱۰ رقمی فقط ۳۳ بیت آنتروپی دارد.
> اگر هش کد بدون فلفل ذخیره شود، هر کسی که یک نسخهٔ پایگاه داده را به دست آورد
> می‌تواند تمام ۱۰^۱۰ کد ممکن را در حدود **۵.۲ ساعت CPU** آفلاین امتحان کند —
> محدودیت نرخ سرور هیچ کمکی نمی‌کند چون حمله به سرور وصل نمی‌شود.
> با فلفل و PBKDF2، هزینه از چند ساعت به حدود **۷ سال CPU** می‌رسد.
>
> اگر این متغیر تنظیم نشده باشد، سرور **آگاهانه با کد 503 خطا می‌دهد** و هرگز
> بی‌سروصدا به هش بدون فلفل برنمی‌گردد.

---

## ۲. اجرا روی سرور

```bash
cd DuoLink/server
node serve.js \
  --host 0.0.0.0 \
  --port 8443 \
  --https \
  --tls-key /etc/letsencrypt/live/YOUR-DOMAIN/privkey.pem \
  --tls-cert /etc/letsencrypt/live/YOUR-DOMAIN/fullchain.pem \
  --db /var/lib/duolink/duolink.sqlite
```

سرور **هیچ وابستگی npm ندارد** — نه `express`، نه `ws`، نه `sqlite3`. همه چیز با
ماژول‌های داخلی Node نوشته شده. پس `npm install` لازم نیست و سطح حمله کوچک است.

### اجرای دائمی با systemd

```ini
# /etc/systemd/system/duolink.service
[Unit]
Description=DuoLink signaling server
After=network.target

[Service]
Type=simple
User=duolink
WorkingDirectory=/opt/duolink/server
EnvironmentFile=/etc/duolink/pepper.env
ExecStart=/usr/bin/node serve.js --host 0.0.0.0 --port 8443 --https \
  --tls-key /etc/letsencrypt/live/YOUR-DOMAIN/privkey.pem \
  --tls-cert /etc/letsencrypt/live/YOUR-DOMAIN/fullchain.pem \
  --db /var/lib/duolink/duolink.sqlite
Restart=on-failure
RestartSec=5

# Hardening: the server only needs its own data directory and certs.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/duolink
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

```bash
sudo install -d -o duolink -g duolink /var/lib/duolink
sudo install -d -m 700 -o root -g root /etc/duolink
# pepper.env باید فقط برای root و سرویس خواندنی باشد:
echo "DUOLINK_ACTIVATION_PEPPER=$(openssl rand -hex 32)" | sudo tee /etc/duolink/pepper.env
sudo chmod 600 /etc/duolink/pepper.env
sudo systemctl enable --now duolink
```

---

## ۳. بررسی سلامت

```bash
curl -s https://YOUR-DOMAIN/healthz
```

باید چیزی شبیه این برگردد:

```json
{"status":"ok","protocolVersion":1,"serverTimeEpochSec":...,"retention":{...},"invitationsByState":{...}}
```

و اطلاعات پروتکل:

```bash
curl -s https://YOUR-DOMAIN/v1/server-info
```

---

## ۴. تنظیم آدرس در برنامه

روی **هر دو گوشی**:

1. صفحهٔ اصلی ← «اتصال به گوشی دیگر»
2. پایین صفحه ← **«تنظیمات سرور ارتباط»**
3. آدرس `https://YOUR-DOMAIN` را وارد کنید (**بدون** مسیر اضافه، بدون `/` انتهایی که اشکال ندارد)
4. **«ذخیره و استفاده»**
5. **«آزمایش اتصال به سرور»** — اگر سبز شد، سرور در دسترس است

> **هر دو گوشی باید دقیقاً همان آدرس را داشته باشند.** آدرس متفاوت یعنی دو اتاق
> جداگانه و کد هیچ‌وقت پیدا نمی‌شود.

---

## ۵. پشتیبان‌گیری

فقط یک فایل اهمیت دارد: پایگاه دادهٔ SQLite.

```bash
# پشتیبان‌گیری سازگار با نوشتن هم‌زمان:
sqlite3 /var/lib/duolink/duolink.sqlite ".backup /backup/duolink-$(date +%F).sqlite"
```

کلید امضای رسید (`server-receipt-key.pem`) در کنار پایگاه داده ساخته می‌شود. اگر
آن را از دست بدهید، جفت‌سازی‌های موجود نمی‌شکنند، اما رسیدهای جدید با کلید دیگری
امضا می‌شوند. **آن را همراه پایگاه داده پشتیبان بگیرید.**

هر دو فایل دادهٔ حساس‌اند: پایگاه داده هش کدها را دارد و کلید امضا کلید خصوصی است.
هر دو را با مجوز `600` و فقط برای کاربر سرویس نگه دارید.

---

## عیب‌یابی

| نشانه | علت محتمل | راه‌حل |
|---|---|---|
| «اتصال به سرور برقرار نشد» در آزمایش اتصال | سرور بالا نیست، یا DNS/فایروال | `curl https://YOUR-DOMAIN/healthz` را از همان شبکه امتحان کنید |
| سرور با 503 پاسخ می‌دهد | `DUOLINK_ACTIVATION_PEPPER` تنظیم نشده | بخش ۱ را ببینید |
| «آدرس سرور معتبر نیست» | `http://` یا داشتن مسیر اضافه | فقط `https://host` بدهید |
| «سرور پاسخ داد اما پاسخ مربوط به DuoLink نیست» | دامنه به سرویس دیگری اشاره می‌کند | DNS و reverse proxy را بررسی کنید |
| کد پیدا نمی‌شود | دو گوشی به آدرس‌های متفاوت وصل‌اند | هر دو را یکسان کنید |
| خطای مجوز گواهی | گواهی منقضی یا زنجیرهٔ ناقص | `fullchain.pem` را استفاده کنید، نه `cert.pem` |

---

## آنچه هنوز انجام نشده

این نکته باید صریح گفته شود:

- **هیچ سرور عمومی توسط توسعه‌دهنده میزبانی نشده است.** شما باید خودتان یکی بالا
  بیاورید، یا از کسی که آن را بالا آورده آدرس بگیرید.
- **سرور امضای دعوت‌نامهٔ صاحب را تأیید نمی‌کند** (`verifiesSpkSignature: false`).
  این یعنی سرور می‌تواند یک دعوت‌نامهٔ جعلی بسازد؛ تأیید نهایی همیشه روی گوشی و با
  مقایسهٔ کد ۶۰ رقمی انجام می‌شود. اگر این را نمی‌پذیرید، از روش QR استفاده کنید.
- **محدودیت نرخ در پایگاه داده است، نه در حافظهٔ فرایند.** جدول `rate_events` در
  همان SQLite نگه داشته می‌شود و شمارش تلاش‌های ناموفق هم روی خود دعوت‌نامه ذخیره
  می‌شود. یعنی سطل تلاش‌ها با ری‌استارت سرور صفر نمی‌شود (که مهم است: وگرنه هر بار
  ری‌استارت، بودجهٔ حمله را تازه می‌کرد). برای چند نمونهٔ هم‌زمان باید همان فایل
  SQLite مشترک باشد؛ اگر هر نمونه پایگاه دادهٔ جدا داشته باشد، بودجه‌ها هم جدا می‌شوند.
