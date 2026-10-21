# CryptoHunterAI
Personal AI assistant for crypto research and mobile repair

یک اپ تک‌صفحه‌ای فارسی (RTL) برای پیگیری پروژه‌های کریپتو (ایردراپ، تست‌نت و ...)، پورتفوی، تراکنش‌ها و گزارش.
همهٔ داده‌ها را کاربر وارد می‌کند و در مرورگر (localStorage) ذخیره می‌شود؛ قیمت زنده یا کشف خودکار پروژه وجود ندارد.

## ساختار پروژه

```
index.html            ساختار صفحه (هدر، منو، صفحه‌ها، مودال‌ها)
css/style.css         همهٔ استایل‌ها
js/utils.js           ثابت‌ها، state پیش‌فرض و توابع کمکی (uid, num, fmt, faDate, escapeHTML, safeUrl)
js/storage.js         loadState / saveState / toast
js/ui.js              ناوبری بین صفحه‌ها و باز و بسته کردن مودال‌ها
js/projects.js        بخش پروژه‌ها
js/assets.js          بخش دارایی‌ها و پورتفوی
js/transactions.js    بخش تراکنش‌ها
js/dashboard.js       داشبورد و گزارش‌ها
js/backup.js          پشتیبان‌گیری، بازیابی و پاک‌سازی داده
js/app.js             updateAll و راه‌اندازی اولیه
```

ترتیب بارگذاری اسکریپت‌ها در `index.html` مهم است (همان ترتیب بالا). فایل‌ها اسکریپت معمولی هستند نه ماژول،
چون دکمه‌ها از `onclick` استفاده می‌کنند و توابع باید سراسری بمانند.
