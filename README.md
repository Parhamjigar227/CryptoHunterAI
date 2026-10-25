# CryptoHunterAI
Personal AI assistant for crypto research and mobile repair

دستیار تحقیق پروژه‌های رمزارزی (ایردراپ، توکن، نشانه‌های کلاهبرداری) روی Cloudflare Workers.
کاربر نام پروژه / وب‌سایت / آدرس قرارداد را می‌دهد؛ برنامه منابع واقعی را می‌خواند (سایت رسمی، GitHub، CoinGecko)،
با Workers AI تحلیل می‌کند و گزارش فارسی با لینک منابع، علائم هشدار و میزان اطمینان می‌دهد.
فقط تحقیق می‌کند: هیچ تراکنش، اتصال کیف پول یا امضایی انجام نمی‌دهد.

> **وضعیت دقیق و آزمون‌ها:** [`STATUS.md`](STATUS.md) — گزارش بازبینی هر قسمت: [`docs/reviews/`](docs/reviews/)

## ساختار
```
src/worker.js            API و سرو فایل‌ها: GET /api/health ، POST /api/research (استریم NDJSON)
src/validate.js          اعتبارسنجی ورودی و URL (دفاع SSRF سطح نام میزبان)
src/safe-fetch.js        fetch امن: timeout، سقف حجم، ریدایرکت دستی با اعتبارسنجی هر گام
src/sources/*.js         منابع: website، github، coingecko (هر کدام رکورد با لینک، زمان و محدودیت‌ها)
src/research.js          اجرای منابع و جمع‌کردن شواهد
src/analyze.js           پرامپت ضد تزریق، فراخوانی Workers AI، پاکسازی خروجی مدل
src/report.js            بخش‌های قطعی گزارش: جدول منابع، علائم هشدار، اطمینان (کد حساب می‌کند، نه مدل)
public/                  رابط کاربری فارسی (صفحهٔ تحقیق + ردیاب محلی پروژه/دارایی/تراکنش)
tests/                   آزمون‌های واحد، سرتاسری و مرورگر
wrangler.jsonc           تنظیمات Cloudflare (binding هوش مصنوعی، مدل، فایل‌های استاتیک)
```

## اجرای آزمون‌ها
```
npm test              # آزمون‌های واحد/سرتاسری (Node ≥ 20؛ بدون شبکه)
npm run test:e2e      # آزمون مرورگر (نیاز به Playwright + Chromium؛ مسیر با PLAYWRIGHT_MODULE)
```
در آزمون‌ها منابع بیرونی و هوش مصنوعی **شبیه‌سازی‌شده‌اند**. آزمون زنده با Workers AI و اینترنت واقعی باید روی حساب خودت انجام شود (پایین).

## راه‌اندازی و استقرار روی Cloudflare (قدم‌به‌قدم)
نیازمند حساب رایگان Cloudflare. مدل پیش‌فرض `@cf/meta/llama-3.3-70b-instruct-fp8-fast` است (مدل قبلی Gemma 3 در مستندات Deprecated شده)؛ با `AI_MODEL` در `wrangler.jsonc` قابل تغییر است. Workers AI سهمیهٔ رایگان ۱۰٬۰۰۰ Neuron در روز دارد (طبق مستندات کلودفلر)؛ بیشتر از آن یا خطا می‌دهد یا (روی پلن پولی) هزینه دارد.

1. `npm install`
2. `npx wrangler login` — در مرورگر وارد حساب Cloudflare شو.
3. **(توصیه‌شده)** توکن دسترسی بگذار تا غریبه‌ها سهمیهٔ رایگان تو را مصرف نکنند:
   `npx wrangler secret put ACCESS_TOKEN` — مقدار را فقط در همین خط فرمان وارد کن، هیچ‌جا ننویس و در گیت‌هاب نگذار.
4. **(اختیاری)** `npx wrangler secret put COINGECKO_API_KEY` اگر CoinGecko بدون کلید خطا داد (کلید رایگان Demo).
   **(اختیاری)** برای جلوگیری از محدودیت نرخ GitHub: `npx wrangler secret put GITHUB_TOKEN` (توکن فقط‌خواندنِ داده‌های عمومی).
5. آزمایش محلی: `npx wrangler dev` (binding هوش مصنوعی از سهمیهٔ حساب تو استفاده می‌کند).
6. استقرار: `npx wrangler deploy`.
7. **آزمون زنده بعد از استقرار** (هنوز انجام نشده): در صفحه، پروژه‌ای واقعی مثل «Uniswap» با `https://uniswap.org` بده و گزارش را بخوان؛ نتیجه (خوب یا بد) را در `STATUS.md` ثبت کن.

هیچ کلید API لازم نیست؛ هوش مصنوعی با binding وصل است و در مرورگر یا مخزن هیچ Secret ی نیست.

## ملاحظات
- فایل `.assetsignore` در ریشه از قبل بود؛ چون فایل‌های استاتیک اکنون در `public/` هستند اثری ندارد ولی حذف نشد.
- اگر مخزن به Cloudflare (Workers Builds) وصل است، مرج شدن به `main` ممکن است استقرار خودکار بزند؛ قبل از مرج بررسی کن.
